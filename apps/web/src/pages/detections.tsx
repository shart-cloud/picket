import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listDetections, setDetectionEnabled } from "../api";
import { EmptyState, ErrorState, LoadingState } from "../ui";

export function DetectionsPage() {
  const queryClient = useQueryClient();
  const detections = useQuery({ queryKey: ["detections"], queryFn: listDetections });
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => setDetectionEnabled(id, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["detections"] })
  });

  if (detections.isLoading) return <LoadingState label="Loading detections" />;
  if (detections.isError) return <ErrorState error={detections.error} />;
  if (!detections.data || detections.data.length === 0) return <EmptyState title="No detection rules found" />;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Detection Rules</h2>
        <span>{detections.data.length} rules</span>
      </div>
      <div className="list-stack">
        {detections.data.map((rule) => (
          <div className="rule-card" key={rule.id}>
            <div>
              <strong>{rule.title}</strong>
              <small>{rule.source} · {rule.execution} · {rule.severity}</small>
            </div>
            <button
              className={rule.enabled ? "button secondary" : "button"}
              disabled={toggle.isPending}
              onClick={() => toggle.mutate({ id: rule.id, enabled: !rule.enabled })}
            >
              {rule.enabled ? "Disable" : "Enable"}
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}
