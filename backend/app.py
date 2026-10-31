# =============================================================================
# app.py — Secure Cloud API entry-point
# =============================================================================
import os

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Config
from routes.auth import auth_bp
from routes.file import file_bp

API_PREFIX = "/api"


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH

    CORS(
        app,
        resources={r"/*": {"origins": Config.CORS_ORIGINS}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        expose_headers=["Content-Disposition", "X-IV", "X-Salt", "X-Original-Mime"],
    )

    @app.before_request
    def log_request():
        print(f"Incoming Request: {request.method} {request.path} from {request.remote_addr}")

    app.register_blueprint(auth_bp, url_prefix=API_PREFIX)
    app.register_blueprint(file_bp, url_prefix=API_PREFIX)

    @app.route("/health", methods=["GET"])
    @app.route(f"{API_PREFIX}/health", methods=["GET"])
    def health():
        try:
            from utils.db import client

            client.admin.command("ping")
            mongo_status = "connected"
        except Exception:
            mongo_status = "disconnected"

        b2_status = "connected" if (Config.B2_KEY_ID and Config.B2_APPLICATION_KEY and Config.B2_BUCKET_NAME) else "not_configured"

        return jsonify(
            {
                "success": True,
                "status": "Backend running",
                "mongo": mongo_status,
                "storage": b2_status,
                "endpoints": [
                    f"POST {API_PREFIX}/register",
                    f"POST {API_PREFIX}/login",
                    f"POST {API_PREFIX}/upload",
                    f"GET {API_PREFIX}/files",
                    f"POST {API_PREFIX}/download/<file_id>",
                    f"DELETE {API_PREFIX}/files/<file_id>",
                ],
            }
        )

    @app.route("/", methods=["GET"])
    def root():
        return jsonify(
            {
                "success": True,
                "status": "ok",
                "health": f"{API_PREFIX}/health",
                "msg": "Secure Cloud API Ready",
            }
        )

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"success": False, "msg": "Endpoint not found"}), 404

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"success": False, "msg": "Payload too large"}), 413

    @app.errorhandler(500)
    def server_error(_):
        return jsonify({"success": False, "msg": "Internal server error"}), 500

    return app


app = create_app()


if __name__ == "__main__":
    
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=True, host="0.0.0.0", port=port)
