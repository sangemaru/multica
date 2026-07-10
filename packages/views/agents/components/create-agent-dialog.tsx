"use client";

import { useState } from "react";
import { Globe, Layers3, Lock } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ModelDropdown } from "./model-dropdown";
import { RuntimePicker, isRuntimeUsableForUser } from "./runtime-picker";
import { InstructionsEditor } from "./instructions-editor";
import { SkillMultiSelect } from "./skill-multi-select";
import { AvatarUploadControl } from "../../common/avatar-upload-control";
import { api } from "@multica/core/api";
import { useWorkspaceId } from "@multica/core/hooks";
import { workspaceKeys } from "@multica/core/workspace/queries";
import { spaceListOptions } from "@multica/core/spaces";
import type {
  Agent,
  AgentAvailabilityMode,
  RuntimeDevice,
  MemberWithUser,
  CreateAgentRequest,
  Space,
} from "@multica/core/types";
import { isImeComposing } from "@multica/core/utils";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@multica/ui/components/ui/dialog";
import { Button } from "@multica/ui/components/ui/button";
import { Checkbox } from "@multica/ui/components/ui/checkbox";
import { Input } from "@multica/ui/components/ui/input";
import { Label } from "@multica/ui/components/ui/label";
import { toast } from "sonner";
import { AGENT_DESCRIPTION_MAX_LENGTH } from "@multica/core/agents";
import { CharCounter } from "./char-counter";
import { useT } from "../../i18n";

export function CreateAgentDialog({
  runtimes,
  runtimesLoading,
  members,
  currentUserId,
  template,
  squadId,
  onClose,
  onCreate,
}: {
  runtimes: RuntimeDevice[];
  runtimesLoading?: boolean;
  members: MemberWithUser[];
  currentUserId: string | null;
  // When provided, the dialog opens in "Duplicate" mode: the visible
  // fields (name / description / runtime / Availability / model) are
  // pre-populated from this agent, and the hidden fields
  // (instructions / custom_args / custom_env / max_concurrent_tasks)
  // are forwarded to the create call so the new agent is a true clone.
  // Skills are copied separately by the caller after createAgent
  // succeeds — they're not part of CreateAgentRequest.
  template?: Agent | null;
  // When set, every successful create is followed by
  // addSquadMember(squadId, agent) so the new agent joins this squad.
  // If the squad-join call fails the agent still exists and the dialog
  // surfaces a warning toast — the user can add it manually from the
  // Members tab.
  squadId?: string;
  onClose: () => void;
  // Returns the created Agent so the dialog can run a follow-up
  // setAgentSkills with the IDs the user picked in the form. Pre-skill-
  // section callers can keep returning `void`; the dialog tolerates a
  // falsy return (no follow-up runs).
  onCreate: (data: CreateAgentRequest) => Promise<Agent | void>;
}) {
  const { t } = useT("agents");
  const isDuplicate = !!template;
  const queryClient = useQueryClient();
  const wsId = useWorkspaceId();
  const {
    data: spaces = [],
    isLoading: spacesLoading,
    isError: spacesError,
  } = useQuery(spaceListOptions(wsId));
  // Name defaults: duplicate uses "<original> copy". Manual-create starts blank.
  const [name, setName] = useState(
    template ? `${template.name}${t(($) => $.create_dialog.duplicate_copy_suffix)}` : "",
  );
  const [description, setDescription] = useState(template?.description ?? "");
  const templateHasLegacyAudience =
    template?.permission_mode === "public_to" &&
    !(template.invocation_targets ?? []).some(
      (target) => target.target_type === "workspace",
    );
  const templateAvailability: AgentAvailabilityMode = templateHasLegacyAudience
    ? "private"
    : template?.availability_mode ??
      (template?.permission_mode === "private" ||
      template?.visibility === "private"
        ? "private"
        : "workspace");
  // Availability is a first-class product setting and is never hidden behind
  // the Composio feature flag. New Web/Desktop agents keep the existing
  // Workspace default; older CLI clients that omit the field remain Private
  // through the server's compatibility path.
  const [availabilityMode, setAvailabilityMode] =
    useState<AgentAvailabilityMode>(templateAvailability);
  const [selectedSpaceIds, setSelectedSpaceIds] = useState<Set<string>>(
    () => new Set(template?.availability_space_ids ?? []),
  );
  const [availabilityDirty, setAvailabilityDirty] = useState(false);
  const activeSpaceIds = new Set(
    spaces.filter((space) => !space.archived_at).map((space) => space.id),
  );
  const selectedSpacesInvalid =
    availabilityMode === "selected_spaces" &&
    (selectedSpaceIds.size === 0 ||
      [...selectedSpaceIds].some((id) => !activeSpaceIds.has(id)) ||
      spacesLoading ||
      spacesError);

  const [model, setModel] = useState(template?.model ?? "");
  const [instructions, setInstructions] = useState(template?.instructions ?? "");
  const [avatarUrl, setAvatarUrl] = useState<string | null>(template?.avatar_url ?? null);
  const [selectedSkillIds, setSelectedSkillIds] = useState<Set<string>>(
    () => new Set(template?.skills.map((s) => s.id) ?? []),
  );
  const [creating, setCreating] = useState(false);

  // Duplicate-mode pre-fill: clone lands on the source agent's runtime so
  // the user doesn't have to re-pick. Skipped when that runtime is now
  // locked for the caller (Create would 403). Empty fallback hands the
  // job to RuntimePicker — it owns filter state, so it's the only place
  // that knows which runtimes are visible right now.
  const [selectedRuntimeId, setSelectedRuntimeId] = useState(() => {
    const templateRuntime = template?.runtime_id
      ? runtimes.find((r) => r.id === template.runtime_id)
      : undefined;
    if (templateRuntime && isRuntimeUsableForUser(templateRuntime, currentUserId)) {
      return templateRuntime.id;
    }
    return "";
  });

  const selectedRuntime = runtimes.find((d) => d.id === selectedRuntimeId) ?? null;
  // Defense-in-depth: even if a locked runtime somehow ends up selected
  // (e.g. duplicate of an agent whose template runtime is now locked, and
  // the workspace has no usable fallback), gate Create on it so we don't
  // submit a request the backend will reject with 403.
  const selectedRuntimeLocked =
    selectedRuntime != null &&
    !isRuntimeUsableForUser(selectedRuntime, currentUserId);

  // Shared squad-join follow-up. Returns nothing — the caller has
  // already shown its create-success toast; we only need to surface a
  // warning when the agent landed but the squad-join failed. Cache
  // invalidation for the squad's members list rides along so the
  // Members tab re-renders without a manual refetch.
  const attachToSquad = async (agentId: string, displayName: string) => {
    if (!squadId) return;
    try {
      await api.addSquadMember(squadId, {
        member_type: "agent",
        member_id: agentId,
      });
      if (wsId) {
        queryClient.invalidateQueries({
          queryKey: [...workspaceKeys.squads(wsId), squadId, "members"],
        });
        queryClient.invalidateQueries({
          queryKey: [...workspaceKeys.squads(wsId), squadId],
        });
      }
    } catch (err) {
      toast.warning(
        t(($) => $.create_dialog.squad_join_failed_toast, {
          name: displayName,
          error: err instanceof Error ? err.message : "unknown error",
        }),
      );
    }
  };

  const handleSubmit = async () => {
    if (!name.trim() || !selectedRuntime || selectedRuntimeLocked) return;
    setCreating(true);

    try {
      const trimmedInstructions = instructions.trim();
      const data: CreateAgentRequest = {
        name: name.trim(),
        description: description.trim(),
        runtime_id: selectedRuntime.id,
        model: model.trim() || undefined,
        instructions: trimmedInstructions || undefined,
        avatar_url: avatarUrl ?? undefined,
      };
      // Only send the new fields. The new backend atomically synchronises its
      // legacy invocation rows; an older backend safely ignores these fields
      // and therefore keeps its deny-by-default Private create behaviour.
      // Sending `public_to + workspace` from the client would make a claimed
      // Selected-Spaces choice become Workspace-wide on an older server.
      data.availability_mode = availabilityMode;
      data.availability_space_ids =
        availabilityMode === "selected_spaces" ? [...selectedSpaceIds] : [];
      if (template) {
        // Duplicate path: forward the hidden config fields the source
        // agent had so the clone is functional out of the box (args /
        // concurrency). Skills flow through the dialog form. As of
        // MUL-2600 the agent resource shape no longer carries
        // custom_env values, so duplication cannot copy env at all —
        // the user has to re-set env on the clone via the env tab
        // (which now goes through the audited `/env` endpoint). The
        // dialog's create call still accepts custom_env at create
        // time, but the source values aren't available here.
        if (template.custom_args.length) data.custom_args = template.custom_args;
        if (template.max_concurrent_tasks) {
          data.max_concurrent_tasks = template.max_concurrent_tasks;
        }
      }
      const createdAgent = await onCreate(data);
      // Follow-up: attach selected skills to the newly created agent.
      // onCreate returns the created Agent for this path; if the caller
      // doesn't return it we fall back to skipping (preserves
      // backward compatibility with non-skill-aware callers).
      if (createdAgent && selectedSkillIds.size > 0) {
        try {
          await api.setAgentSkills(createdAgent.id, {
            skill_ids: [...selectedSkillIds],
          });
          if (wsId) {
            queryClient.invalidateQueries({ queryKey: workspaceKeys.agents(wsId) });
          }
        } catch (skillErr) {
          // Non-fatal: agent exists, skills can be added on the detail
          // page. Surface as a warning toast so the user knows.
          toast.warning(
            t(($) => $.create_dialog.skill_attach_failed_toast, {
              error:
                skillErr instanceof Error ? skillErr.message : "unknown error",
            }),
          );
        }
      }
      // Squad context: attach the agent after skills land so the
      // squad's Members tab shows the agent with its skills already
      // in place. Atomicity is best-effort by design (see plan in
      // MUL-2178) — a partial failure surfaces a warning toast and
      // the user can retry from the Add Member dialog.
      if (createdAgent && squadId) {
        await attachToSquad(createdAgent.id, createdAgent.name);
      }
      onClose();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t(($) => $.create_dialog.create_failed_toast));
      setCreating(false);
    }
  };

  const headerTitle = isDuplicate
    ? t(($) => $.create_dialog.title_duplicate)
    : t(($) => $.create_dialog.title_create);

  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="p-0 gap-0 flex flex-col overflow-hidden !top-1/2 !left-1/2 !-translate-x-1/2 !-translate-y-1/2 !w-full !max-w-2xl !h-[85vh]">
        <DialogHeader className="border-b px-5 py-3 space-y-0">
          <DialogTitle className="text-base font-semibold">{headerTitle}</DialogTitle>
          {isDuplicate && template && (
            <DialogDescription className="mt-1 text-xs">
              {t(($) => $.create_dialog.description_duplicate, { name: template.name })}
            </DialogDescription>
          )}
          {!isDuplicate && (
            <DialogDescription className="mt-1 text-xs">
              {t(($) => $.create_dialog.description_create)}
            </DialogDescription>
          )}
        </DialogHeader>

        <div className="flex-1 overflow-y-auto p-5">
          <div className="space-y-4 min-w-0">
            {/* Identity row: avatar (left) + name & description stack
                (right). The avatar visually anchors the identity of
                what the user is creating; pairing it with the Name
                field reads as "this is the agent's face + name",
                same shape as detail-page header so the affordance is
                instantly familiar. */}
            <div className="flex items-start gap-4">
              <AvatarUploadControl
                variant="agent"
                value={avatarUrl}
                name={name}
                size={64}
                onUploaded={setAvatarUrl}
                onClear={() => setAvatarUrl(null)}
              />
              <div className="flex-1 min-w-0 space-y-3">
                <div>
                  <Label className="text-xs text-muted-foreground">{t(($) => $.create_dialog.name_label)}</Label>
                  <Input
                    autoFocus
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder={t(($) => $.create_dialog.name_placeholder)}
                    className="mt-1"
                    onKeyDown={(e) => {
                      if (isImeComposing(e)) return;
                      if (e.key === "Enter") handleSubmit();
                    }}
                  />
                </div>

                <div>
                  <Label className="text-xs text-muted-foreground">{t(($) => $.create_dialog.description_label)}</Label>
                  <Input
                    type="text"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder={t(($) => $.create_dialog.description_placeholder)}
                    maxLength={AGENT_DESCRIPTION_MAX_LENGTH}
                    className="mt-1"
                  />
                  <div className="mt-1">
                    <CharCounter
                      length={[...description].length}
                      max={AGENT_DESCRIPTION_MAX_LENGTH}
                    />
                  </div>
                </div>
              </div>
            </div>

            <AvailabilitySection
              mode={availabilityMode}
              onModeChange={(next) => {
                setAvailabilityDirty(true);
                setAvailabilityMode(next);
              }}
              selectedSpaceIds={selectedSpaceIds}
              onSelectedSpaceIdsChange={(next) => {
                setAvailabilityDirty(true);
                setSelectedSpaceIds(next);
              }}
              spaces={spaces}
              spacesLoading={spacesLoading}
              spacesError={spacesError}
              legacyCustom={templateHasLegacyAudience && !availabilityDirty}
            />

            <RuntimePicker
              runtimes={runtimes}
              runtimesLoading={runtimesLoading}
              members={members}
              currentUserId={currentUserId}
              selectedRuntimeId={selectedRuntimeId}
              onSelect={setSelectedRuntimeId}
            />

            <ModelDropdown
              runtimeId={selectedRuntime?.id ?? null}
              runtimeOnline={selectedRuntime?.status === "online"}
              value={model}
              onChange={setModel}
              disabled={!selectedRuntime}
            />

            {/* --- Optional sections (instructions / skills) ---
                Collapsed by default so quick-create stays fast.
                Duplicate pre-fills everything from the source agent. */}
            <InstructionsEditor
              value={instructions}
              onChange={setInstructions}
              placeholder={
                isDuplicate
                  ? t(($) => $.create_dialog.instructions.placeholder_duplicate)
                  : t(($) => $.create_dialog.instructions.placeholder_blank)
              }
            />

            <SkillMultiSelect
              selectedIds={selectedSkillIds}
              onChange={setSelectedSkillIds}
            />
          </div>
        </div>

        {/* Inline footer instead of <DialogFooter>: the shipped
            DialogFooter applies `-mx-4 -mb-4` assuming a padded
            DialogContent (default `p-4`). Our DialogContent uses
            `p-0`, so those negative margins push the footer outside
            the dialog. A plain flex row anchored by `border-t` keeps
            the visual rhythm without the overflow bug. */}
        <div className="flex items-center justify-end gap-2 border-t bg-background px-5 py-3">
          <Button variant="ghost" onClick={onClose}>
            {t(($) => $.create_dialog.cancel)}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={
              creating ||
              !name.trim() ||
              !selectedRuntime ||
              selectedRuntimeLocked ||
              selectedSpacesInvalid
            }
            title={
              selectedRuntimeLocked
                ? t(($) => $.create_dialog.runtime_private_locked_tooltip)
                : undefined
            }
          >
            {creating ? t(($) => $.create_dialog.creating) : t(($) => $.create_dialog.create)}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}


function AvailabilitySection({
  mode,
  onModeChange,
  selectedSpaceIds,
  onSelectedSpaceIdsChange,
  spaces,
  spacesLoading,
  spacesError,
  legacyCustom,
}: {
  mode: AgentAvailabilityMode;
  onModeChange: (next: AgentAvailabilityMode) => void;
  selectedSpaceIds: Set<string>;
  onSelectedSpaceIdsChange: (next: Set<string>) => void;
  spaces: Space[];
  spacesLoading: boolean;
  spacesError: boolean;
  legacyCustom: boolean;
}) {
  const { t } = useT("agents");
  const activeSpaces = spaces.filter((space) => !space.archived_at);
  const archivedSelected = spaces.filter(
    (space) => !!space.archived_at && selectedSpaceIds.has(space.id),
  );
  const knownSpaceIds = new Set(spaces.map((space) => space.id));
  const unknownSelected = [...selectedSpaceIds].filter(
    (id) => !knownSpaceIds.has(id),
  );

  const toggleSpace = (spaceId: string, checked: boolean) => {
    const next = new Set(selectedSpaceIds);
    if (checked) next.add(spaceId);
    else next.delete(spaceId);
    onSelectedSpaceIdsChange(next);
  };

  const optionClass = (selected: boolean) =>
    `flex min-w-0 flex-1 items-start gap-2 rounded-lg border px-3 py-2.5 text-sm transition-colors ${
      selected
        ? "border-primary bg-primary/5"
        : "border-border hover:bg-muted"
    }`;

  return (
    <div>
      <Label className="text-xs text-muted-foreground">
        {t(($) => $.create_dialog.availability.label)}
      </Label>
      {legacyCustom && (
        <div className="mt-1.5 rounded-md bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-400">
          {t(($) => $.create_dialog.availability.legacy_custom_hint)}
        </div>
      )}
      <div className="mt-1.5 grid grid-cols-3 gap-2">
        <button
          type="button"
          onClick={() => onModeChange("private")}
          className={optionClass(!legacyCustom && mode === "private")}
        >
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 text-left">
            <div className="font-medium">
              {t(($) => $.create_dialog.availability.private_title)}
            </div>
            <div className="text-xs text-muted-foreground">
              {t(($) => $.create_dialog.availability.private_desc)}
            </div>
          </div>
        </button>
        <button
          type="button"
          onClick={() => onModeChange("selected_spaces")}
          className={optionClass(
            !legacyCustom && mode === "selected_spaces",
          )}
        >
          <Layers3 className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 text-left">
            <div className="font-medium">
              {t(($) => $.create_dialog.availability.spaces_title)}
            </div>
            <div className="text-xs text-muted-foreground">
              {t(($) => $.create_dialog.availability.spaces_desc)}
            </div>
          </div>
        </button>
        <button
          type="button"
          onClick={() => onModeChange("workspace")}
          className={optionClass(!legacyCustom && mode === "workspace")}
        >
          <Globe className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 text-left">
            <div className="font-medium">
              {t(($) => $.create_dialog.availability.workspace_title)}
            </div>
            <div className="text-xs text-muted-foreground">
              {t(($) => $.create_dialog.availability.workspace_desc)}
            </div>
          </div>
        </button>
      </div>

      {mode === "selected_spaces" && !legacyCustom && (
        <div className="mt-2 rounded-lg border bg-muted/30 px-3 py-2">
          {spacesLoading ? (
            <div className="text-xs text-muted-foreground">
              {t(($) => $.create_dialog.availability.spaces_loading)}
            </div>
          ) : spacesError ? (
            <div className="text-xs text-destructive">
              {t(($) => $.create_dialog.availability.spaces_error)}
            </div>
          ) : (
            <div className="max-h-40 overflow-y-auto">
              {activeSpaces.length === 0 && (
                <div className="text-xs text-muted-foreground">
                  {t(($) => $.create_dialog.availability.spaces_empty)}
                </div>
              )}
              {activeSpaces.map((space) => (
                <label
                  key={space.id}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-1 py-1 text-sm hover:bg-background/60"
                >
                  <Checkbox
                    checked={selectedSpaceIds.has(space.id)}
                    onCheckedChange={(value) =>
                      toggleSpace(space.id, value === true)
                    }
                    aria-label={space.name}
                  />
                  <span className="min-w-0 flex-1 truncate">{space.name}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {space.key}
                  </span>
                </label>
              ))}
              {archivedSelected.map((space) => (
                <label
                  key={space.id}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-1 py-1 text-sm text-muted-foreground"
                >
                  <Checkbox
                    checked
                    onCheckedChange={(value) =>
                      toggleSpace(space.id, value === true)
                    }
                    aria-label={space.name}
                  />
                  <span className="min-w-0 flex-1 truncate line-through">
                    {space.name}
                  </span>
                  <span className="text-[10px]">
                    {t(($) => $.create_dialog.availability.archived_badge)}
                  </span>
                </label>
              ))}
              {unknownSelected.map((spaceId) => (
                <label
                  key={spaceId}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-1 py-1 text-sm text-muted-foreground"
                >
                  <Checkbox
                    checked
                    onCheckedChange={(value) =>
                      toggleSpace(spaceId, value === true)
                    }
                    aria-label={t(
                      ($) => $.create_dialog.availability.unavailable_space,
                    )}
                  />
                  <span className="min-w-0 flex-1 truncate line-through">
                    {t(
                      ($) => $.create_dialog.availability.unavailable_space,
                    )}
                  </span>
                </label>
              ))}
            </div>
          )}
          {selectedSpaceIds.size === 0 && (
            <div className="mt-1 text-xs text-amber-700 dark:text-amber-400">
              {t(($) => $.create_dialog.availability.select_one_hint)}
            </div>
          )}
          {(archivedSelected.length > 0 || unknownSelected.length > 0) && (
            <div className="mt-1 text-xs text-amber-700 dark:text-amber-400">
              {t(($) => $.create_dialog.availability.remove_unavailable_hint)}
            </div>
          )}
        </div>
      )}

      <div className="mt-1.5 text-[11px] text-muted-foreground">
        {t(($) => $.create_dialog.availability.work_access_note)}
      </div>
    </div>
  );
}
