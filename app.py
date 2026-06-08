from __future__ import annotations

import re
from datetime import datetime
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "student-secret-key-lab5"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lab5.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Для доступа к этой странице необходимо пройти аутентификацию."
login_manager.login_message_category = "warning"


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(64), nullable=True)
    first_name = db.Column(db.String(64), nullable=False)
    middle_name = db.Column(db.String(64), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    role = db.relationship("Role")

    @property
    def full_name(self) -> str:
        parts = [self.last_name or "", self.first_name or "", self.middle_name or ""]
        return " ".join(part for part in parts if part).strip() or "(без ФИО)"


class VisitLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User")


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def is_admin() -> bool:
    return bool(current_user.is_authenticated and current_user.role and current_user.role.name == "Администратор")


def has_right(action: str, target_user: User | None = None) -> bool:
    if not current_user.is_authenticated:
        return False

    if is_admin():
        return action in {"create_user", "edit_user", "view_profile", "delete_user", "view_logs"}

    # Для себя: обычный пользователь работает только со своими данными.
    if action == "edit_user":
        return target_user is not None and current_user.id == target_user.id
    if action == "view_profile":
        return target_user is not None and current_user.id == target_user.id
    if action == "view_logs":
        return True

    return False


def check_rights(action: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            target_user = None
            user_id = kwargs.get("user_id")
            if user_id is not None:
                target_user = db.session.get(User, user_id)

            if not has_right(action, target_user):
                flash("У вас недостаточно прав для доступа к данной странице.", "danger")
                return redirect(url_for("index"))
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Пароль должен содержать минимум 8 символов."
    if len(password) > 128:
        return "Пароль должен содержать максимум 128 символов."
    if re.search(r"\s", password):
        return "Пароль не должен содержать пробелы."
    if not re.search(r"[A-ZА-ЯЁ]", password):
        return "Нужна хотя бы одна заглавная буква."
    if not re.search(r"[a-zа-яё]", password):
        return "Нужна хотя бы одна строчная буква."
    if not re.search(r"[0-9]", password):
        return "Нужна хотя бы одна цифра."

    allowed_pattern = r"""^[A-Za-zА-Яа-яЁё0-9~!?@#$%^&*_\-+\(\)\[\]\{\}><\/\\|"'.,:;]+$"""
    if not re.match(allowed_pattern, password):
        return "Пароль содержит недопустимые символы."
    return None


def validate_user_form(form_data, is_create: bool) -> dict[str, str]:
    errors: dict[str, str] = {}

    username = form_data.get("username", "").strip()
    password = form_data.get("password", "")
    last_name = form_data.get("last_name", "").strip()
    first_name = form_data.get("first_name", "").strip()

    if is_create:
        if not username:
            errors["username"] = "Поле не может быть пустым."
        elif not re.match(r"^[A-Za-z0-9]{5,}$", username):
            errors["username"] = "Логин: только латиница/цифры, минимум 5 символов."
        if not password:
            errors["password"] = "Поле не может быть пустым."
        else:
            password_error = validate_password(password)
            if password_error:
                errors["password"] = password_error

    if not last_name:
        errors["last_name"] = "Поле не может быть пустым."
    if not first_name:
        errors["first_name"] = "Поле не может быть пустым."

    return errors


def seed_data():
    if not Role.query.first():
        db.session.add_all(
            [
                Role(name="Администратор", description="Полные права"),
                Role(name="Пользователь", description="Базовые права"),
            ]
        )
        db.session.commit()

    admin_role = Role.query.filter_by(name="Администратор").first()
    user_role = Role.query.filter_by(name="Пользователь").first()

    if not User.query.filter_by(username="admin").first():
        db.session.add(
            User(
                username="admin",
                password_hash=generate_password_hash("Admin123!"),
                last_name="Сидоров",
                first_name="Админ",
                middle_name="Главный",
                role_id=admin_role.id if admin_role else None,
            )
        )

    if not User.query.filter_by(username="user01").first():
        db.session.add(
            User(
                username="user01",
                password_hash=generate_password_hash("User123!"),
                last_name="Кузнецов",
                first_name="Илья",
                middle_name="Алексеевич",
                role_id=user_role.id if user_role else None,
            )
        )

    db.session.commit()


def can(action: str, target_user: User | None = None) -> bool:
    return has_right(action, target_user)


app.jinja_env.globals["can"] = can
app.jinja_env.globals["is_admin"] = is_admin


@app.before_request
def log_visit():
    if request.path.startswith("/static/"):
        return
    # Для себя: пишем журнал посещений каждой страницы.
    log = VisitLog(path=request.path[:100], user_id=current_user.id if current_user.is_authenticated else None)
    db.session.add(log)
    db.session.commit()


@app.route("/")
def index():
    users = User.query.order_by(User.id).all()
    return render_template("index.html", users=users)


@app.route("/users/<int:user_id>")
@login_required
@check_rights("view_profile")
def user_view(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден.", "warning")
        return redirect(url_for("index"))
    return render_template("user_view.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember_me"))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            flash("Вы успешно вошли в систему.", "success")
            return redirect(request.args.get("next") or url_for("index"))

        flash("Неверный логин или пароль.", "danger")
        return render_template("login.html", entered_username=username)

    return render_template("login.html", entered_username="")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("index"))


@app.route("/users/create", methods=["GET", "POST"])
@login_required
@check_rights("create_user")
def user_create():
    roles = Role.query.order_by(Role.name).all()
    errors = {}
    form_values = {"username": "", "last_name": "", "first_name": "", "middle_name": "", "role_id": ""}

    if request.method == "POST":
        form_values = dict(request.form)
        errors = validate_user_form(request.form, is_create=True)
        if User.query.filter_by(username=request.form.get("username", "").strip()).first():
            errors["username"] = "Пользователь с таким логином уже существует."

        if errors:
            flash("Исправьте ошибки в форме.", "danger")
            return render_template("user_create.html", roles=roles, errors=errors, form_values=form_values)

        try:
            role_value = request.form.get("role_id")
            new_user = User(
                username=request.form["username"].strip(),
                password_hash=generate_password_hash(request.form["password"]),
                last_name=request.form["last_name"].strip(),
                first_name=request.form["first_name"].strip(),
                middle_name=request.form.get("middle_name", "").strip() or None,
                role_id=int(role_value) if role_value else None,
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Пользователь успешно создан.", "success")
            return redirect(url_for("index"))
        except SQLAlchemyError:
            db.session.rollback()
            flash("Ошибка при сохранении пользователя.", "danger")

    return render_template("user_create.html", roles=roles, errors=errors, form_values=form_values)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@check_rights("edit_user")
def user_edit(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден.", "warning")
        return redirect(url_for("index"))

    roles = Role.query.order_by(Role.name).all()
    errors = {}
    form_values = {
        "last_name": user.last_name or "",
        "first_name": user.first_name or "",
        "middle_name": user.middle_name or "",
        "role_id": str(user.role_id or ""),
    }

    if request.method == "POST":
        form_values = dict(request.form)
        errors = validate_user_form(request.form, is_create=False)
        if errors:
            flash("Исправьте ошибки в форме.", "danger")
            return render_template(
                "user_edit.html", user=user, roles=roles, errors=errors, form_values=form_values
            )

        try:
            user.last_name = request.form["last_name"].strip()
            user.first_name = request.form["first_name"].strip()
            user.middle_name = request.form.get("middle_name", "").strip() or None

            if is_admin():
                role_value = request.form.get("role_id")
                user.role_id = int(role_value) if role_value else None

            db.session.commit()
            flash("Данные пользователя обновлены.", "success")
            return redirect(url_for("index"))
        except SQLAlchemyError:
            db.session.rollback()
            flash("Ошибка при сохранении изменений.", "danger")

    return render_template("user_edit.html", user=user, roles=roles, errors=errors, form_values=form_values)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@check_rights("delete_user")
def user_delete(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден.", "warning")
        return redirect(url_for("index"))
    if user.id == current_user.id:
        flash("Нельзя удалить самого себя.", "danger")
        return redirect(url_for("index"))

    try:
        db.session.delete(user)
        db.session.commit()
        flash("Пользователь удален.", "success")
    except SQLAlchemyError:
        db.session.rollback()
        flash("Ошибка при удалении пользователя.", "danger")
    return redirect(url_for("index"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    errors = {}
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        new_password_repeat = request.form.get("new_password_repeat", "")

        if not check_password_hash(current_user.password_hash, old_password):
            errors["old_password"] = "Старый пароль введен неверно."

        new_password_error = validate_password(new_password)
        if new_password_error:
            errors["new_password"] = new_password_error

        if new_password != new_password_repeat:
            errors["new_password_repeat"] = "Новые пароли не совпадают."

        if errors:
            flash("Не удалось изменить пароль. Проверьте данные.", "danger")
            return render_template("change_password.html", errors=errors)

        try:
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Пароль успешно изменен.", "success")
            return redirect(url_for("index"))
        except SQLAlchemyError:
            db.session.rollback()
            flash("Ошибка при изменении пароля.", "danger")

    return render_template("change_password.html", errors=errors)


from reports import create_reports_blueprint

reports_bp = create_reports_blueprint(db, VisitLog, User, check_rights, is_admin)
app.register_blueprint(reports_bp)


with app.app_context():
    db.create_all()
    seed_data()


if __name__ == "__main__":
    app.run(debug=True)
