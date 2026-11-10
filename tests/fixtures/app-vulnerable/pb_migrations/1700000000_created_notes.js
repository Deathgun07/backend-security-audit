/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const collection = new Collection({
    name: "notes",
    type: "base",
    listRule: "",
    viewRule: "",
    createRule: "@request.auth.id != ''",
    updateRule: "@request.auth.id != ''",
    deleteRule: "",
    fields: [
      { type: "text", name: "content" },
      { type: "relation", name: "owner", collectionId: "_pb_users_auth_" },
    ],
  });
  return app.save(collection);
});
