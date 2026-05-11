import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

const MIN_PATCH_UI_MODE = ["1", "true", "yes", "on"].includes(
  String(import.meta.env.VITE_MIN_PATCH_UI || "false").trim().toLowerCase()
);
const PRODUCT_SITE_MODE = ["1", "true", "yes", "on"].includes(
  String(import.meta.env.VITE_PRODUCT_SITE || "false").trim().toLowerCase()
);

const appLoader = PRODUCT_SITE_MODE
  ? () => import("./AppWebsite")
  : MIN_PATCH_UI_MODE
    ? () => import("./AppMin")
    : () => import("./App");

void appLoader().then(({ default: AppComponent }) => {
  ReactDOM.createRoot(document.getElementById("root")).render(
    <BrowserRouter>
      <AppComponent />
    </BrowserRouter>
  );
});
