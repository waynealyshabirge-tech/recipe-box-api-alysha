# Security baseline – 2026-10-01

- Anonymous `GET /recipes` returns all recipes, including `is_public: false` (e.g. id 3, "Secret family hot sauce").
- Anonymous `POST /recipes` creates a new recipe (e.g. id 4, "Test recipe from anonymous user").
- Anonymous `DELETE /recipes/4` deletes the previously created recipe.
