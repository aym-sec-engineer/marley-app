# ═══════════════════ STAGE 1 — Build ═══════════════════
FROM python:3.11-alpine AS builder

WORKDIR /app
RUN apk add --no-cache gcc libffi-dev musl-dev

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt gunicorn

# ═══════════════════ STAGE 2 — Runtime (minimal, sans pip/setuptools) ═══════════════════
FROM python:3.11-alpine

WORKDIR /app

COPY --from=builder /root/.local /home/marley/.local
COPY . .

# Purge RÉELLE de pip/setuptools/wheel natifs de l'image de base
# (ils ne servent à RIEN à l'exécution — seule source des CVE msgpack/setuptools)
RUN rm -rf /usr/local/lib/python3.11/site-packages/pip* \
           /usr/local/lib/python3.11/site-packages/setuptools* \
           /usr/local/lib/python3.11/site-packages/wheel* \
           /usr/local/lib/python3.11/ensurepip \
           /usr/local/bin/pip* \
    && find /usr/local/lib/python3.11/site-packages -maxdepth 1 -type d -name "*.dist-info" \
         \( -iname "pip-*" -o -iname "setuptools-*" -o -iname "wheel-*" \) -exec rm -rf {} +

RUN addgroup -g 986 dockerhost && adduser -D marley && adduser marley dockerhost && chown -R marley:marley /app /home/marley/.local

USER marley
ENV PATH=/home/marley/.local/bin:$PATH
ENV PYTHONPATH=/home/marley/.local/lib/python3.11/site-packages

EXPOSE 5000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "main:app"]