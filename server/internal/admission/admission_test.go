package admission

import (
	"context"
	"testing"
)

func TestCompatibilityEvaluatorReturnsTypedObserveOnlyDecision(t *testing.T) {
	decision, err := (CompatibilityEvaluator{}).Evaluate(context.Background(), Request{Path: PathMention})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed || !decision.ObserveOnly {
		t.Fatalf("decision = %+v, want allowed observe-only", decision)
	}
	if decision.PolicyVersion == "" || decision.ReasonCode == "" {
		t.Fatalf("decision lacks stable metadata: %+v", decision)
	}
}

func TestPathVocabularyRejectsUnknown(t *testing.T) {
	if ValidPath(Path("future_unreviewed_path")) {
		t.Fatal("unknown dispatch path must not be valid")
	}
	for _, path := range AllPaths() {
		if !ValidPath(path) {
			t.Fatalf("declared path %q is invalid", path)
		}
	}
}
