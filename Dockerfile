FROM python:3.11-alpine

WORKDIR /app

# Installation des dépendances système minimales
RUN apk add --no-cache gcc libffi-dev musl-dev

# Copie et installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copie du code source
COPY . .

# Création d'un utilisateur non-root (hardening conteneur)
RUN adduser -D marley && chown -R marley:marley /app
USER marley

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "main:app"]