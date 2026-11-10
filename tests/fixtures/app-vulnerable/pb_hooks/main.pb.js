/// <reference path="../pb_data/types.d.ts" />
routerAdd("GET", "/api/notes/search", (e) => {
  const q = e.request.url.query().get("q");
  const rows = arrayOf(new DynamicModel({ id: "", content: "" }));
  $app.db().newQuery("SELECT id, content FROM notes WHERE content LIKE '%" + q + "%'").all(rows);
  return e.json(200, rows);
});
