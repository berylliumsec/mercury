import React from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import { App } from "./App";
import { applyTheme, readThemePreference } from "./theme";
import "./styles.css";

// Set the theme before the first render so the page never flashes the wrong palette.
applyTheme(readThemePreference());

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
