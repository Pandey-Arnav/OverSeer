export const PROTECTED_FIELDS = ["recipient", "amount", "accountNumber", "routingNumber"];

export function readTransaction(form) {
  return Object.fromEntries(PROTECTED_FIELDS.map((name) => [name, form.elements[name]?.value ?? ""]));
}

export function cloneTransaction(transaction) { return { ...transaction }; }
