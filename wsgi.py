import click, sys, csv
from tabulate import tabulate
from models import db, Todo, Admin, RegularUser, db, User
from sqlalchemy.exc import IntegrityError
from app import app

db.init_app(app)


@app.cli.command("init", help="Creates and initializes the database")
def initialize():
  db.drop_all()
  db.create_all()
 
  bob = RegularUser('bob', 'bob@mail.com', 'bobpass')
  rick = RegularUser('rick', 'rick@mail.com', 'rickpass')
  sally = RegularUser('sally', 'sally@mail.com', 'sallypass')
  pam = Admin('11232', 'pam', 'pam@mail.com', 'pampass')
  db.session.add_all([bob, rick, sally, pam])  #add all can save multiple objects at once
  db.session.commit()
  #load todo data from csv file
  with open('todos.csv') as file:
    reader = csv.DictReader(file)
    for row in reader:
      new_todo = Todo(text=row['text'])  #create object
      #update fields based on records
      new_todo.done = True if row['done'] == 'true' else False
      new_todo.user_id = int(row['user_id'])
      db.session.add(new_todo)  #queue changes for saving
    db.session.commit()
    #save all changes OUTSIDE the loop
  print('database intialized')


@app.cli.command("get-user", help="Retrieves a User by username or id")
@click.argument('key', default='bob')
def get_user(key):
  bob = RegularUser.query.filter_by(username=key).first()
  if not bob:
    bob = RegularUser.query.get(int(key))
    if not bob:
      print(f'{key} not found!')
      return
  print(bob)


@app.cli.command("change-email")
@click.argument('username', default='bob')
@click.argument('email', default='bob@mail.com')
def change_email(username, email):
  bob = RegularUser.query.filter_by(username=username).first()
  if not bob:
    print(f'{username} not found!')
    return
  bob.email = email
  db.session.add(bob)
  db.session.commit()
  print(bob)


@app.cli.command('get-users')
def get_users():
  users = User.query.all()
  print(users)


@app.cli.command('create-user')
@click.argument('username', default='rick')
@click.argument('email', default='rick@mail.com')
@click.argument('password', default='rickpass')
def create_user(username, email, password):
  newuser = RegularUser(username, email, password)
  try:
    db.session.add(newuser)
    db.session.commit()
  except IntegrityError as e:
    db.session.rollback()
    print(e.orig)
    print("Username or email already taken!")
  else:
    print(newuser)


@app.cli.command('delete-user')
@click.argument('username', default='bob')
def delete_user(username):
  bob = RegularUser.query.filter_by(username=username).first()
  if not bob:
    print(f'{username} not found!')
    return
  db.session.delete(bob)
  db.session.commit()
  print(f'{username} deleted')


@app.cli.command('add-todo')
@click.argument('username', default='bob')
@click.argument('text', default='wash car')
def add_task(username, text):
  bob = RegularUser.query.filter_by(username=username).first()
  if not bob:
    print(f'{username} not found!')
    return
  new_todo = Todo(text)
  bob.todos.append(new_todo)
  db.session.add(bob)
  db.session.commit()
  print('Todo added!')


@app.cli.command('get-todos')
@click.argument('username', default='bob')
def get_user_todos(username):
  bob = RegularUser.query.filter_by(username=username).first()
  if not bob:
    print(f'{username} not found!')
    return
  print(bob.todos)


@click.argument('todo_id', default=1)
@click.argument('username', default='bob')
@app.cli.command('toggle-todo')
def toggle_todo_command(todo_id, username):
  user = RegularUser.query.filter_by(username=username).first()
  if not user:
    print(f'{username} not found!')
    return

  todo = Todo.query.filter_by(id=todo_id, user_id=user.id).first()
  if not todo:
    print(f'{username} has no todo id {todo_id}')

  todo.toggle()
  print(f'{todo.text} is {"done" if todo.done else "not done"}!')


@click.argument('category', default='chores')
@click.argument('username', default='bob')
@click.argument('todo_id', default=1)
@app.cli.command('add-category', help="Adds a category to a todo")
def add_todo_category_command(
    category,
    todo_id,
    username,
):
  user = User.query.filter_by(username=username).first()
  if not user:
    print(f'user {username} not found!')
    return

  res = user.add_todo_category(todo_id, category)
  if not res:
    print(f'{username} has no todo id {todo_id}')
    return

  todo = Todo.query.get(todo_id)
  print(todo)


@app.cli.command('list-todos')
def list_todos():
  #tabulate package needs to work with an array of arrays
  data = []
  for todo in Todo.query.all():
    data.append(
        [todo.text, todo.done, todo.user.username,
         todo.get_cat_list()])
  print(tabulate(data, headers=["Text", "Done", "User", "Categories"]))
