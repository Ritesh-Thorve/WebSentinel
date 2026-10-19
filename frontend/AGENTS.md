<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## WebSentinel architecture
- Keep the single scanner screen at `/`; no workspace shell or secondary feature routes, to preserve the minimal workflow.
- Keep scan creation and reads behind the existing typed ScannerApi HTTP adapter; missing configuration must fail rather than select a mock adapter.
- Use a TanStack Query mutation followed by ID-keyed polling for user-initiated scans; never automatically resubmit POST requests or invent progress.
- Omit authorization_confirmed unless the caller explicitly supplies true; a URL submission must not manufacture target authorization.
- Render only available backend finding fields as redacted React text; never trust evidence as HTML.
- Live adapters must enforce authenticated ownership, explicit target authorization, connection-time IP/DNS and redirect checks, timeouts, and request budgets server-side; browser validation is not a security boundary.
