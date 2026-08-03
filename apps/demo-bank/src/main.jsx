import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { DemoProvider } from "./context/DemoContext.jsx";
import "./styles.css";
import "./demo.css";

createRoot(document.getElementById("root")).render(<DemoProvider><App /></DemoProvider>);
