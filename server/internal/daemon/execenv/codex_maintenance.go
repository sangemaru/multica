package execenv

import (
	"fmt"
	"os"
	"path/filepath"
)

// prepareCodexMaintenanceHome has no shared-home resolver, copy, skill loader,
// memory opt-out environment switch or session-store lookup. An existing home
// is rejected rather than reused or seeded then stripped.
func prepareCodexMaintenanceHome(env *Environment, params PrepareParams) error {
	policy := params.CodexMaintenance
	home := filepath.Join(env.RootDir, codexHomeDirName)
	if err := os.Mkdir(home, 0o700); err != nil {
		return fmt.Errorf("maintenance: fresh codex-home required: %w", err)
	}
	isolated, err := policy.Environment(home, params.CodexMaintenanceProviderEnv)
	if err != nil {
		return err
	}
	for key, path := range isolated {
		if key == "HOME" || key == "TMPDIR" || len(key) > 4 && key[:4] == "XDG_" {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return fmt.Errorf("maintenance: create runtime directory: %w", err)
			}
		}
	}
	config, err := policy.Config(params.CodexExecutable)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(home, "config.toml"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("maintenance: create native config: %w", err)
	}
	_, writeErr := file.Write(config)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if policy.AuthFile != "" {
		// This is the one explicit credential source. Linking does not read,
		// discover or copy auth, and does not prove provider/model uptake.
		if err := os.Symlink(policy.AuthFile, filepath.Join(home, "auth.json")); err != nil {
			return fmt.Errorf("maintenance: link explicit auth_file: %w", err)
		}
	}
	env.CodexHome = home
	env.CodexMaintenanceEnv = isolated
	return nil
}
