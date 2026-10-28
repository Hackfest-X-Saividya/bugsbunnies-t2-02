import { ArrowDown, ArrowRight, ArrowUpRight, Braces, Crosshair, LockKeyhole, Shield, Sparkles } from "lucide-react";
import { Link, useLocation, useNavigate } from "react-router-dom";

const features = [
  { icon: Braces, title: "Intelligent code analysis", text: "Spot risky patterns in Python projects with findings designed to give developers useful context." },
  { icon: Crosshair, title: "API endpoint discovery", text: "Map routes in your FastAPI application and quickly find routes missing from documentation." },
  { icon: Sparkles, title: "AI security insights", text: "Turn complex scanner signals into clear explanations and practical remediation guidance." },
];

export default function LandingPage() {
  const navigate = useNavigate();
  const location = useLocation();

  return <main className="landing-page">
    <header className="landing-nav">
      <Link to="/" className="brand"><span className="brand-mark"><Shield size={20} /></span><span><strong>ShadowGuard</strong><small>AI SECURITY PLATFORM</small></span></Link>
      <nav><a href="#workflow" onClick={(event) => { event.preventDefault(); document.getElementById("workflow")?.scrollIntoView({ behavior: "instant", block: "start" }); window.history.replaceState(null, "", "#workflow"); }}>How it works</a><span className="landing-divider" /><button type="button" className="button button-quiet nav-signin" onClick={() => navigate("/dashboard", { state: { demoMessage: "Demo sign-in only — no authentication took place. You are viewing the local demonstration workspace." } })}>Demo sign in <ArrowUpRight size={14} /></button><Link to="/scan" className="button button-primary nav-cta">Start scanning <ArrowRight size={15} /></Link></nav>
    </header>
    {location.state?.demoMessage && <div className="landing-demo-message" role="status"><Shield size={14} />{location.state.demoMessage}</div>}
    <section className="hero-section">
      <div className="hero-grid">
        <div className="hero-copy">
          <div className="hero-kicker"><span className="pulse-dot" /> SECURITY INTELLIGENCE FOR DEVELOPERS</div>
          <h1>Know what’s hiding<br />in your <span>application.</span></h1>
          <p className="hero-tagline">Beyond the code. Behind every endpoint.</p>
          <p className="hero-subtitle">Uncover code-level risks, map every API route, and connect findings to the endpoints they affect — all in one developer-first workspace.</p>
          <div className="hero-actions"><Link to="/scan" className="button button-primary button-large">Start scanning <ArrowRight size={17} /></Link><a href="#features" className="button button-quiet button-large">Explore features <ArrowDown size={16} /></a></div>
          <div className="hero-trust"><LockKeyhole size={15} /><span>Built for your security workflow</span><i /> <span>Python · FastAPI</span></div>
        </div>
        <div className="hero-visual">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <div className="visual-glow" />
          <div className="hero-shield"><Shield size={82} strokeWidth={1.2} /><div className="shield-check">✓</div></div>
          <div className="floating-card float-findings"><div className="float-icon danger"><Crosshair size={15} /></div><div><strong>5 findings mapped</strong><span>Across 5 API endpoints</span></div><b className="float-pulse" /></div>
          <div className="floating-card float-route"><div className="float-icon cyan"><Braces size={15} /></div><div><strong>Route discovered</strong><span>POST /internal/export</span></div><span className="float-flag">UNDOCUMENTED</span></div>
          <div className="visual-caption"><span className="caption-line" /> A clearer view of your attack surface</div>
        </div>
      </div>
    </section>
    <section className="feature-section" id="features">
      <div className="section-heading"><span className="eyebrow">ONE SECURITY WORKSPACE</span><h2>See the whole picture.</h2><p>Bring source-code signals and API context together to make security work more actionable.</p></div>
      <div className="feature-grid">{features.map(({ icon: Icon, title, text }, index) => <article className="feature-card" key={title}><div className={`feature-icon feature-icon-${index}`}><Icon size={20} /></div><div className="feature-index">0{index + 1}</div><h3>{title}</h3><p>{text}</p><Link to="/dashboard">Explore capability <ArrowRight size={14} /></Link></article>)}</div>
    </section>
    <section className="workflow-section" id="workflow">
      <div className="workflow-copy"><span className="eyebrow">A MORE CONNECTED REVIEW</span><h2>From upload to<br /><span>endpoint insight.</span></h2><p>ShadowGuard brings code scanning and route discovery into a single flow, so you can move from a finding to the context that matters.</p><Link className="button button-outline" to="/scan">Try the demo <ArrowRight size={16} /></Link></div>
      <div className="workflow-steps">
        {[["01", "Add a project", "Select a Python project archive or explore the built-in demo."], ["02", "Map the surface", "Review discovered endpoints and documentation mismatches."], ["03", "Investigate & improve", "Trace scanner findings to routes and review suggested fixes."]].map(([number, title, text]) => <div className="workflow-step" key={number}><span>{number}</span><div><strong>{title}</strong><p>{text}</p></div></div>)}
      </div>
    </section>
    <footer className="landing-footer"><Link to="/" className="brand"><span className="brand-mark"><Shield size={18} /></span><span><strong>ShadowGuard</strong><small>AI SECURITY PLATFORM</small></span></Link><span>Designed to make application security more actionable.</span><span>© 2026 ShadowGuard AI · Hack Fest 2026</span></footer>
  </main>;
}
