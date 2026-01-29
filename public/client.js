export async function api(path, method = "GET", body) {
  const opts = { method, headers: {} };
  if (body) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Eroare");
  return data;
}

export function qs(id) {
  return document.getElementById(id);
}

export function setText(id, txt) {
  qs(id).textContent = txt;
}