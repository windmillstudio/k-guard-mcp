router.get('/profiles/19/:id', async (req, res) => res.json(await db.findUnique({ where: { id: req.params.id, ownerId: req.user.id } })));
