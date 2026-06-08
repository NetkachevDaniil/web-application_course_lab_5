from __future__ import annotations

import csv
import io

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func


def create_reports_blueprint(db, VisitLog, User, check_rights, is_admin):
    reports_bp = Blueprint("reports", __name__, url_prefix="/logs")

    @reports_bp.route("/")
    @login_required
    @check_rights("view_logs")
    def logs_index():
        page = request.args.get("page", 1, type=int)
        query = VisitLog.query.order_by(VisitLog.created_at.desc())
        if not is_admin():
            query = query.filter(VisitLog.user_id == current_user.id)

        pagination = query.paginate(page=page, per_page=10, error_out=False)
        return render_template("reports/logs_index.html", pagination=pagination)

    @reports_bp.route("/pages")
    @login_required
    @check_rights("view_logs")
    def pages_report():
        query = db.session.query(VisitLog.path, func.count(VisitLog.id).label("total")).group_by(VisitLog.path)
        if not is_admin():
            query = query.filter(VisitLog.user_id == current_user.id)
        rows = query.order_by(func.count(VisitLog.id).desc()).all()
        return render_template("reports/pages_report.html", rows=rows)

    @reports_bp.route("/users")
    @login_required
    @check_rights("view_logs")
    def users_report():
        query = db.session.query(VisitLog.user_id, func.count(VisitLog.id).label("total")).group_by(VisitLog.user_id)
        if not is_admin():
            query = query.filter(VisitLog.user_id == current_user.id)
        rows = query.order_by(func.count(VisitLog.id).desc()).all()
        user_map = {user.id: user.full_name for user in User.query.all()}
        return render_template("reports/users_report.html", rows=rows, user_map=user_map)

    @reports_bp.route("/pages/export")
    @login_required
    @check_rights("view_logs")
    def pages_report_export():
        query = db.session.query(VisitLog.path, func.count(VisitLog.id).label("total")).group_by(VisitLog.path)
        if not is_admin():
            query = query.filter(VisitLog.user_id == current_user.id)
        rows = query.order_by(func.count(VisitLog.id).desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Страница", "Количество посещений"])
        for path, total in rows:
            writer.writerow([path, total])

        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=pages_report.csv"},
        )

    @reports_bp.route("/users/export")
    @login_required
    @check_rights("view_logs")
    def users_report_export():
        query = db.session.query(VisitLog.user_id, func.count(VisitLog.id).label("total")).group_by(VisitLog.user_id)
        if not is_admin():
            query = query.filter(VisitLog.user_id == current_user.id)
        rows = query.order_by(func.count(VisitLog.id).desc()).all()
        user_map = {user.id: user.full_name for user in User.query.all()}

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Пользователь", "Количество посещений"])
        for user_id, total in rows:
            full_name = user_map.get(user_id, "Неаутентифицированный пользователь") if user_id else "Неаутентифицированный пользователь"
            writer.writerow([full_name, total])

        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=users_report.csv"},
        )

    return reports_bp
