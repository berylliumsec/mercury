export function isStaticDemoMode(): boolean {
  return import.meta.env.MODE === "demo" || import.meta.env.VITE_STATIC_DEMO === "1";
}
