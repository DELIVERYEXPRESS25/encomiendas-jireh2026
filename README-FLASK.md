# Encomienda Jireh: Flask, SQLAlchemy y SQL

La interfaz existente de `index.html` se conserva. Flask sirve la aplicación y Flask-SQLAlchemy persiste los datos en tablas relacionadas. La app solicita una clave antes de mostrar la interfaz y protege las rutas API. La clave compartida se configura con `JIREH_ADMIN_PASSWORD` o se cambia desde la aplicación. La clave maestra se valida solo en el servidor y nunca se muestra en la interfaz ni en las respuestas API; quien haya iniciado sesión puede cambiar la clave compartida desde **Cambiar clave de acceso** confirmando su clave actual. SQLite es el modo predeterminado y PostgreSQL está disponible con Psycopg 3.

## Iniciar en macOS o Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python serve.py
```

Abre <http://127.0.0.1:5000>. Configura las claves locales con `JIREH_ADMIN_PASSWORD` y `JIREH_MASTER_PASSWORD`; sus valores no se guardan en los archivos versionados. Usa **Cambiar clave de acceso** en la barra lateral para definir una nueva clave compartida y confirma la clave actual (la normal o la maestra). Se guarda un hash protegido en `instance/jireh_auth_config.json` y el cambio cierra las sesiones anteriores. La maestra solo se cambia desde la configuración del servidor con `JIREH_MASTER_PASSWORD`; nunca aparece en la app. Las claves de desarrollo almacenadas en `instance/jireh_admin_password` y `instance/jireh_master_password` están excluidas de Git. La sesión vence después de 8 horas y **Salir** la cierra. La clave de firma de sesión se genera una vez en `instance/jireh_secret.key`; ambos archivos están excluidos de Git. En producción, configura `JIREH_COOKIE_SECURE=1` junto con HTTPS. La base SQLite predeterminada está en `instance/encomienda_jireh.sqlite3`; `JIREH_DB_PATH` permite indicar otra ruta. Cada guardado se hace en una transacción, actualiza una revisión y registra una huella SHA-256 en auditoría. Las relaciones usan claves foráneas y borrado en cascada; SQLite activa WAL, claves foráneas y sincronización completa.

Flask-Migrate administra las revisiones en `alembic/`. La carpeta `migrations/` conserva la migración SQL histórica del esquema original. La base SQLite existente se registró en la revisión inicial de Alembic sin recrear tablas ni borrar información. Para cambios futuros usa `flask --app app db migrate -m "descripcion"` y revisa el archivo antes de aplicar `flask --app app db upgrade`.

## PostgreSQL

La app seguirá usando SQLite mientras no se configure `DATABASE_URL`. Para PostgreSQL, instala las dependencias y exporta una URL antes de iniciar:

```bash
export DATABASE_URL='postgresql://usuario:clave@localhost:5432/encomienda_jireh'
flask --app app db upgrade
python serve.py
```

Las URL `postgres://` y `postgresql://` se convierten automáticamente al controlador Psycopg 3. En una base PostgreSQL nueva, ejecuta primero las migraciones con `flask --app app db upgrade`; no copies archivos SQLite entre dispositivos.

Waitress sirve la app local en `127.0.0.1` con ocho hilos. Para PythonAnywhere, configura el WSGI para importar `app` como `application`; no ejecutes `serve.py` allí. Define `JIREH_ADMIN_PASSWORD` con una clave compartida, `JIREH_MASTER_PASSWORD` con la clave maestra privada, `JIREH_SECRET_KEY` con un secreto persistente y `JIREH_COOKIE_SECURE=1`. Las claves no se incluyen en Git. Cambia la clave compartida desde la app; la maestra se configura en el WSGI. La maestra no se puede cambiar desde la interfaz. Activa Force HTTPS y descarga respaldos JSON manualmente desde la app; la restauración también se inicia manualmente desde Configuración.

## Configuración de PythonAnywhere

Antes de importar la app desde el archivo WSGI, configura secretos persistentes (no subas estos valores al repositorio):

```python
import os
os.environ["JIREH_ADMIN_PASSWORD"] = "pon-aqui-una-clave-larga-y-unica"
os.environ["JIREH_MASTER_PASSWORD"] = "pon-aqui-una-clave-maestra-privada"
os.environ["JIREH_SECRET_KEY"] = "pon-aqui-un-secreto-aleatorio-largo-y-persistente"
os.environ["JIREH_COOKIE_SECURE"] = "1"
from app import app as application
```

La protección cubre la página, los archivos de la app y `/api/*`. El usuario y la clave son compartidos; no hay perfiles individuales.

## Dependencias de desarrollo

Para instalar las herramientas opcionales de desarrollo:

```bash
python -m pip install -r requirements-dev.txt
```

`pytest` y `pytest-flask` están separados de las dependencias de ejecución. Ejecuta `python -m pytest -q` para validar rutas, lecturas/escrituras ORM, relaciones, validación, conflictos de revisión e integridad; usa `JIREH_DB_PATH` para que las pruebas corran en una base temporal aislada.
