from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from sqlalchemy import ForeignKey
# from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
import flask_login
from flask_login import  UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort

login_manager = LoginManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES
with app.app_context():

    #CREATE TABLE IN DB

    class User(UserMixin, db.Model):
        __tablename__ = "users"
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(100), unique=True)
        password = db.Column(db.String(100))
        name = db.Column(db.String(100))

        # This will act like a List of BlogPost objects attached to each User.
        # The "author" refers to the author property in the BlogPost class.
        posts = relationship("BlogPost", back_populates="author")
        comments = relationship("Comment", back_populates="comment_author")

    class BlogPost(db.Model):
        __tablename__ = "blog_posts"
        id = db.Column(db.Integer, primary_key=True)

        # Create Foreign Key, "users.id" the users refers to the tablename of User.
        author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
        author = relationship("User", back_populates="posts")

        title = db.Column(db.String(250), unique=True, nullable=False)
        subtitle = db.Column(db.String(250), nullable=False)
        date = db.Column(db.String(250), nullable=False)
        body = db.Column(db.Text, nullable=False)
        img_url = db.Column(db.String(250), nullable=False)
        comments = relationship("Comment", back_populates="parent_post")
    # Line below only required once, when creating DB.

    class Comment(db.Model):
        __tablename__ = "comments"
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        comment_author = relationship("User", back_populates="comments")

        # ***************Child Relationship*************#
        post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
        parent_post = relationship("BlogPost", back_populates="comments")
        text = db.Column(db.Text, nullable=False)


    db.create_all()


# Create admin-only decorator
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not '_user_id' in session.keys():
            flash('Page locked, login as admin.')
            return redirect(url_for('login'))
        if int(session['_user_id']) == 1:
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    print(request.method)
    print(form.validate_on_submit())
    if request.method=='POST':
        name = request.form.get('user_name')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        print(user)
        if user != None:
            flash("email already exists!")
            return redirect(url_for("login"))
        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        add_user = User(
            name=name,
            password=password,
            email=email
        )
        print(name)
        db.session.add(add_user)
        db.session.commit()
        print(email)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)

@app.route('/add_new_comment/<post_id>',methods=['GET','POST'])
def add_new_comment(post_id):

    if request.method=='POST':
        new_comment = Comment(
        author_id = current_user.id,
        post_id = post_id,
        text = request.form.get("comment")
        )
        db.session.add(new_comment)
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    error=""
    login_form=LoginForm()
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if user==None:
            flash("Invalid username")
            return render_template("login.html",form=login_form, error=error)
        # Check stored password hash against entered password hashed.

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            error="Invalid Password!"
            flash('You were not successfully logged in',error)
    return render_template("login.html",form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return render_template("index.html")


@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    post_comments=Comment.query.filter_by(post_id=post_id).all()
    print(post_comments)
    form=CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post,cform=form,post_comments=post_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(

            title=request.form.get('title'),
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000,debug=True)
