/// <reference path="../pb_data/types.d.ts" />
const NOTES = "notes";
migrate((app) => {
  const collection = new Collection({
    name: NOTES,
    type: "base",
    listRule: "@request.auth.id != '' && user = @request.auth.id",
    createRule: "@request.auth.id != '' && @request.body.user = @request.auth.id",
    updateRule: "user = @request.auth.id",
    deleteRule: null,
  });
  app.save(collection);
  app.db().newQuery("INSERT INTO `" + NOTES + "` (content, user) VALUES ({:c}, {:u})").bind({ c: "", u: "" }).execute();
});
