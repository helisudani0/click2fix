import { lazy } from "react";

const memoizedLoader = (loader) => {
  let promise = null;
  return () => {
    if (!promise) promise = loader();
    return promise;
  };
};

const lazyWithPreload = (loader) => {
  const Component = lazy(loader);
  Component.preload = loader;
  return Component;
};

const loadLogin = memoizedLoader(() => import("../pages/Login"));
const loadPatchWorkbench = memoizedLoader(() => import("../pages/PatchWorkbenchMin"));

export const Login = lazyWithPreload(loadLogin);
export const PatchWorkbench = lazyWithPreload(loadPatchWorkbench);
