# Con Docker Compose v2+ (recommended)
docker compose up --scale attacker=5 -d

# O con la vieja cli
docker-compose up --scale attacker=5 -d

docker compose logs -f attacker