from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# login manager
login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##Configure User table
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # relationship with Blog(Parent)
    posts = relationship("BlogPost", back_populates="author")
    # relationship with Comment(Parent)
    comments = relationship("Comment", back_populates="author")


##CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #relationship with User(Child)
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")
    #relationship with Comment(Parent)
    comments = relationship("Comment", back_populates="blog")


# COMMENT TABLE
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # relationship with User(Child)
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="comments")
    #relationship with Comment(Child)
    blog_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    blog = relationship("BlogPost", back_populates="comments")

# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    print(f"Here, userid= {user_id}")
    print(User.query.get(user_id))
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    print(f"current_user active: {current_user.is_active}")
    print(f"current_user id: {current_user.get_id()}")
    print(f"current_user id type: {type(current_user.get_id())}")
    posts = BlogPost.query.all()
    # print(posts[0].parent)
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name_to_register = form.name.data
        email_to_register = form.email.data
        password_to_register = form.password.data
        user_query = User.query.filter_by(email=email_to_register).first()
        # check if the user already exists
        if not user_query:
            hashed_password = generate_password_hash(password=password_to_register,
                                                     method='pbkdf2:sha256',
                                                     salt_length=8)
            user_to_add = User(name=name_to_register,
                               password=hashed_password,
                               email=email_to_register)

            db.session.add(user_to_add)
            db.session.commit()
            login_user(user_to_add)
            return redirect(url_for('get_all_posts'))
        else:
            flash("The user already exists")
            return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        login_email = form.email.data
        login_password = form.password.data
        user_query = User.query.filter_by(email=login_email).first()
        # check if the user exists
        if user_query:
            # check if the password is correct
            result = check_password_hash(pwhash=user_query.password, password=login_password)

            if result:
                login_user(user_query)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password is not correct")
        else:
            flash("Email does not exists, please log in")

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    print(current_user.is_authenticated)
    print(current_user.get_id())
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):

    form = CommentForm()

    if form.validate_on_submit():
        # if no user is logged in
        if not current_user.is_authenticated:
            flash("Please log in to comment")
            return redirect(url_for('login'))
        else:
            print("______COMMENT________")
            print(form.body.data)
            print("---------------")
            comment = Comment(text=form.body.data,
                              author_id=current_user.get_id(),
                              blog_id=post_id)
            print("COMMENT INFO")
            print(comment.author_id)
            print(comment.text)
            print(comment.blog_id)
            print("COMMENT INFO")
            db.session.add(comment)
            db.session.commit()

    requested_post = BlogPost.query.get(post_id)
    print(requested_post.comments)
    print(requested_post.comments[0].text)
    print(requested_post.comments[0].author.name)
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    print("DFDSFSDFSD")
    if current_user.get_id() != '1':
        abort(403)

    form = CreatePostForm()

    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.get_id()
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    if current_user.get_id() != '1':
        abort(403)

    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.author = "alex"
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    if current_user.get_id() != '1':
        abort(403)

    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
