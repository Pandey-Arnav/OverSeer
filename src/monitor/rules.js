export const RULES = {
  protectedFieldModified: { id: "protected-field-modified", label: "Protected transaction field modified", points: 50 },
  dynamicScriptInjection: { id: "dynamic-script-injection", label: "Dynamic script injection", points: 35 },
  hiddenIframe: { id: "hidden-iframe", label: "Hidden iframe detected", points: 20 },
  evalDetected: { id: "eval-detected", label: "eval() detected", points: 20 },
  newFunctionDetected: { id: "new-function-detected", label: "new Function() detected", points: 20 },
  largeDomMutation: { id: "large-dom-mutation", label: "Large DOM mutation", points: 15 },
  unknownScriptSource: { id: "unknown-script-source", label: "Unknown script source", points: 25 },
  paymentFormModified: { id: "payment-form-modified", label: "Unexpected payment form modification", points: 25 },
};
