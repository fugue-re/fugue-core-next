export function formatAddress(address: string): string {
  const separator = address.indexOf(":");
  if (separator < 0) return address;
  const space = address.slice(0, separator);
  const offset = address.slice(separator + 1);
  return space === "0x0" ? offset : `${space}:${offset}`;
}

export function offsetOf(address: string): string {
  const separator = address.lastIndexOf(":");
  return separator < 0 ? address : address.slice(separator + 1);
}
