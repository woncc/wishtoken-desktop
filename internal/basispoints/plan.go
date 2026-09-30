package basispoints

import (
	"encoding/json"
	"fmt"
	"strings"
)

// translateNativePlan adapts the gateway's native update_plan call to the
// client's declared update_plan function. It never executes a plan.
func (b *Bridge) translateNativePlan(native object) (object, error) {
	var selected toolInfo
	matches := 0
	for _, key := range []string{"update_plan", "functions.update_plan"} {
		if candidate, ok := b.tools[key]; ok {
			selected = candidate
			matches++
		}
	}
	if matches != 1 || selected.Kind != "function" {
		return nil, fmt.Errorf("native update_plan requires one declared client update_plan function")
	}
	arguments, ok := native["arguments"].(object)
	if !ok {
		if err := decode([]byte(text(native["arguments"])), &arguments); err != nil {
			return nil, fmt.Errorf("native update_plan arguments must be one JSON object")
		}
	}
	steps, ok := arguments["plan"].([]any)
	if !ok {
		return nil, fmt.Errorf("native update_plan requires a plan array")
	}
	plan := make([]any, 0, len(steps))
	for _, value := range steps {
		step, ok := value.(object)
		if !ok {
			return nil, fmt.Errorf("native update_plan entries must be objects")
		}
		description := strings.TrimSpace(firstText(step, "step", "description", "title", "text"))
		if description == "" {
			return nil, fmt.Errorf("native update_plan has a missing step description")
		}
		status := normalizePlanStatus(text(step["status"]))
		if status == "" {
			return nil, fmt.Errorf("native update_plan has an unsupported step status")
		}
		plan = append(plan, object{"step": description, "status": status})
	}
	translated := object{"plan": plan}
	if explanation := firstText(arguments, "explanation", "summary"); explanation != "" {
		translated["explanation"] = explanation
	}
	callID := text(native["call_id"])
	if callID == "" {
		return nil, fmt.Errorf("native update_plan is missing call_id")
	}
	itemID := text(native["id"])
	if itemID == "" {
		itemID = "fc_" + fingerprint(callID)
	}
	encoded, _ := json.Marshal(translated)
	result := object{"type": "function_call", "id": itemID, "call_id": callID, "name": selected.Name, "arguments": string(encoded), "status": "completed"}
	if selected.Namespace != "" {
		result["namespace"] = selected.Namespace
	}
	b.replay.put(b.scope, callID, native, result)
	return result, nil
}

func firstText(m object, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func normalizePlanStatus(status string) string {
	switch strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(status))) {
	case "", "pending", "not_started", "todo", "planned", "queued", "blocked":
		return "pending"
	case "in_progress", "active", "started", "doing", "current", "running":
		return "in_progress"
	case "completed", "complete", "done", "finished":
		return "completed"
	default:
		return ""
	}
}
