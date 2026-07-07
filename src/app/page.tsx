export default function Home() {
  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0a0a0a", color: "#fafafa", fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" }}>
      <div style={{ textAlign: "center", maxWidth: 400 }}>
        <h1 style={{ fontSize: "1.25rem", fontWeight: 600 }}>auth service</h1>
        <p style={{ color: "#737373", fontSize: "0.8rem", marginTop: "0.5rem" }}>
          token issuer for first-party applications
        </p>
        <div style={{ marginTop: "2rem", fontSize: "0.75rem", color: "#525252", lineHeight: "1.8" }}>
          <p>POST /api/v1/register</p>
          <p>POST /api/v1/login</p>
          <p>POST /api/v1/refresh</p>
          <p>POST /api/v1/logout</p>
          <p>GET&nbsp; /.well-known/jwks</p>
        </div>
      </div>
    </div>
  );
}
