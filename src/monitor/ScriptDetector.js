export class ScriptDetector {
  constructor({ eventBus, root = document }) { this.eventBus = eventBus; this.root = root; this.observer = null; this.originalEval = window.eval; this.originalFunction = window.Function; }
  start() {
    for (const iframe of this.root.querySelectorAll("iframe")) this.inspectIframe(iframe);
    this.observer = new MutationObserver((mutations) => {
      const addedCount = mutations.reduce((count, mutation) => count + mutation.addedNodes.length, 0);
      for (const mutation of mutations) {
        if (mutation.type === "attributes" && mutation.target instanceof HTMLIFrameElement) this.inspectIframe(mutation.target);
        for (const node of mutation.addedNodes) {
          if (!(node instanceof Element)) continue;
          if (node instanceof HTMLScriptElement) this.inspectScript(node, "dynamic-script");
          if (node instanceof HTMLIFrameElement) this.inspectIframe(node);
          for (const script of node.querySelectorAll("script")) this.inspectScript(script, "dynamic-script");
          for (const iframe of node.querySelectorAll("iframe")) this.inspectIframe(iframe);
        }
      }
      if (addedCount > 8) this.eventBus.emit("security-finding", { rule: "largeDomMutation", attackType: "dom-mutation" });
    });
    this.observer.observe(this.root.documentElement, { childList: true, subtree: true, attributes: true });
    window.eval = (...args) => { this.eventBus.emit("security-finding", { rule: "evalDetected", attackType: "script-execution" }); return this.originalEval(...args); };
    const detector = this;
    window.Function = function (...args) { detector.eventBus.emit("security-finding", { rule: "newFunctionDetected", attackType: "script-execution" }); return Reflect.construct(detector.originalFunction, args); };
  }
  inspectScript(node, attackType) {
    const source = node.src || "inline script";
    const finding = node.src && !node.src.startsWith(location.origin) ? "unknownScriptSource" : "dynamicScriptInjection";
    this.eventBus.emit("security-finding", { rule: finding, attackType, detail: source });
    if (!node.src && /\b(?:eval|Function)\s*\(|MutationObserver\s*\(/.test(node.textContent || "")) this.eventBus.emit("security-finding", { rule: /MutationObserver/.test(node.textContent || "") ? "largeDomMutation" : "evalDetected", attackType: "inline-script", detail: "inline script heuristic" });
  }
  inspectIframe(node) {
    const style = getComputedStyle(node);
    if (node.hidden || style.display === "none" || style.visibility === "hidden" || node.width === "0" || node.height === "0") {
      this.eventBus.emit("security-finding", { rule: "hiddenIframe", attackType: "hidden-iframe" });
    }
  }
  stop() { this.observer?.disconnect(); window.eval = this.originalEval; window.Function = this.originalFunction; }
}
