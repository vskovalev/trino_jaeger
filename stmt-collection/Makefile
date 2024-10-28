run:
	docker compose up -d
test-allow:
	docker compose exec coordinator trino --debug --user=admin --output-format=MARKDOWN --execute "show catalogs"
test-disallow:
	docker compose exec coordinator trino --debug --user=bob --output-format=MARKDOWN --execute "show catalogs"
clean:
	docker compose down 