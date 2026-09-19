export function Badge({ value }) {
  const cls = String(value).toLowerCase();
  return <span className={`badge badge-${cls}`}>{String(value).replace(/_/g, " ")}</span>;
}
