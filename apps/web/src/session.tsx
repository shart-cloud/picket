import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createAccessSession, getMe, getSession } from "./api";

export function useSession() {
  return useQuery({ queryKey: ["session"], queryFn: getSession, retry: false });
}

export function SessionStatus() {
  const session = useSession();
  const user = session.data?.user;

  if (session.isLoading) return <div className="session-chip muted">Checking session</div>;
  if (session.isError) return <div className="session-chip danger">Session error</div>;
  if (!user) return <div className="session-chip warning">Access verified, app session missing</div>;

  return <div className="session-chip">{user.email ?? user.name ?? user.id ?? "Signed in"}</div>;
}

export function SessionRequiredNotice() {
  const queryClient = useQueryClient();
  const session = useSession();
  const me = useQuery({ queryKey: ["me"], queryFn: getMe, retry: false });
  const bootstrap = useMutation({
    mutationFn: createAccessSession,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["session"] }),
        queryClient.invalidateQueries({ queryKey: ["me"] })
      ]);
    }
  });

  if (session.data?.user) return null;
  const accessEmail = me.data?.access?.email;

  return (
    <div className="notice-card warning">
      <strong>App session required for analyst actions.</strong>
      <span>Cloudflare Access allows read-only views, but alert mutations require a better-auth session.</span>
      <button className="button" disabled={bootstrap.isPending || !accessEmail} onClick={() => bootstrap.mutate()} type="button">
        {bootstrap.isPending ? "Creating session" : `Continue${accessEmail ? ` as ${accessEmail}` : ""}`}
      </button>
      {bootstrap.isError ? <span className="notice-error">{bootstrap.error.message}</span> : null}
    </div>
  );
}
