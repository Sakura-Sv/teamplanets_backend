from flask import Flask, request, g, jsonify, render_template
from itsdangerous import serializer, TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import random
from werkzeug.security import generate_password_hash, check_password_hash
from json import loads, dumps
from threading import Thread
from flask_mail import Message


app = Flask(__name__)

app.config['SECRET_KEY'] = 'the Nebula NCUHome'
app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = '1204736871@qq.com'
app.config['MAIL_PASSWORD'] = 'cdfvdhpfdmxfidcg'
app.config['TP_MAIL_SUBJECT_PREFIX'] = ['Team Planets']
app.config['TP_MAIL_SENDER'] = 'Team Planets Admin <thenebula@qq.com>'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://guest:123456@localhost/new?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
mail = Mail(app)
auth = HTTPTokenAuth(app)


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    user_name = db.Column(db.VARCHAR(16), nullable=False)
    user_email = db.Column(db.VARCHAR(64), nullable=False, unique=True)
    password_hash = db.Column(db.VARCHAR(200), nullable=False)
    user_token = db.Column(db.VARCHAR(200), nullable=False)
    user_active = db.Column(db.Boolean)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def __init__(self, name, password, email):
        self.user_name = name
        password(password)
        self.user_email = email
        self.user_active = False

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Schedule(db.Model):
    __tablename__ = 'schedules'
    schedule_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    schedule_event = db.Column(db.VARCHAR(32), nullable=False)
    schedule_place = db.Column(db.VARCHAR(64))
    schedule_begin = db.Column(db.DateTime, nullable=False)
    schedule_end = db.Column(db.DateTime, nullable=False)
    schedule_senior_name = db.Column(db.VARCHAR(32)) #发布上级主体
    is_deadline = db.Column(db.Boolean, nullable=False)
    hoster_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'))

    def __init__(self, event, place, begintime, endtime, isddl=False, senior_name=None):
        self.schedule_event = event
        self.schedule_place = place
        self.schedule_begin = begintime
        self.schedule_end = endtime
        self.is_deadline = isddl
        self.schedule_senior_name = senior_name


class Team(db.Model):
    __tablename__ = 'teams'
    team_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    team_maker_email = db.Column(db.VARCHAR(64), db.ForeignKey('users.user_email'))
    team_name = db.Column(db.VARCHAR(32), nullable=False)
    team_attr = db.Column(db.VARCHAR(16), nullable=False)
    team_member_num = db.Column(db.INTEGER)

    def __init__(self, email, name, attr):
        self.team_maker_email = email
        self.team_name = name
        self.team_attr = attr
        self.team_member_num = 1


class Department(db.Model):
    __tablename__ = 'departments'
    department_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    department_name = db.Column(db.VARCHAR(32), nullable=False)
    department_senior = db.Column(db.VARCHAR(32), nullable=False)
    department_num = db.Column(db.INTEGER)

    def __init__(self, name, senior, num):
        self.department_name = name
        self.department_senior = senior
        self.department_num = num


class Character(db.Model):
    __tablename__ = 'characters'
    character_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    character_name = db.Column(db.VARCHAR(16), nullable=False)

    def __init__(self):
        #预设
        pass


# class Privilege(db.Model):
#     __tablename__ = 'privileges'
#     privilege_id = db.Column(db.INTEGER, Primary_key=True, autoincrement=True)
#     privilege_value = db.Column(db.INTEGER)
#     character_name = db.Column(db.VARCHAR(16), db.ForeignKey('characters.character_name'))
#
#     def __init__(self):
#         #预设
#         pass


class UserTeamCharacter(db.Model):
    __tablename__ = 'user_team_character'
    '''1 管理员 2 组织者 3 成员'''
    user_team_character_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    user_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'))
    team_id = db.Column(db.INTEGER, db.ForeignKey('teams.team_id'))
    character_id = db.Column(db.INTEGER, db.ForeignKey('characters.character_id'))

    def __init__(self, user, team, character=3):
        self.user_id = user
        self.team_id = team
        self.character_id = character


class Vote(db.Model):
    __tablename__ = 'votes'
    vote_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    vote_name = db.Column(db.VARCHAR(32), nullable=False)
    vote_begin = db.Column(db.DateTime)
    vote_end = db.Column(db.DateTime)

    def __init__(self, name, begintime, endtime):
        self.vote_name = name
        self.vote_begin = begintime
        self.vote_end = endtime


class VoteOption(db.Model):
    __tablename__ = 'vote_options'
    option_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    option_name = db.Column(db.VARCHAR(32), nullable=False)
    option_num = db.Column(db.INTEGER)
    hoster_id = db.Column(db.INTEGER, db.ForeignKey('votes.vote_id'))

    def __init__(self, name):
        self.option_name = name
        self.num = 0


class Notice(db.Model):
    __tablename__ = 'notices'
    notice_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    notice_name = db.Column(db.VARCHAR(16), nullable=False)
    notice_body = db.Column(db.TEXT(250), nullable=False)

    def __init__(self, name, body):
        self.name = name
        self.body = body


class UserVoteSponsor(db.Model):
    __tablename__ = 'user_vote_sponsor'
    user_vote_sponsor_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    user_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'))
    vote_id = db.Column(db.INTEGER, db.ForeignKey('votes.vote_id'))
    is_sponsor = db.Column(db.Boolean)
    have_voting = db.Column(db.Boolean)

    def __init__(self, is_sponsor=True, havevoting=False):
        self.is_sponsor = is_sponsor
        self.have_voting = havevoting


class UserNoticeSponsor(db.Model):
    __tablename__ = 'user_notice_sponsor'
    user_notice_sponsor_id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)
    user_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'))
    notice_id = db.Column(db.INTEGER, db.ForeignKey('notices.notice_id'))
    is_sponsor = db.Column(db.Boolean)

    def __init__(self):
        pass


class InvitationCode(db.Model):
    __tablename__ = 'invitation_codes'
    icode_id = db.Column(db.INTEGER, primary_key=True)
    icode_value = db.Column(db.INTEGER, unique=True)
    team_id = db.Column(db.INTEGER, db.ForeignKey('teams.team_id'))

    def __init__(self,team_id):
        self.icode_value = random.randint(1000000, 9999999)
        self.team_id = team_id


def verify_password(email, password):
    user = User.query.filter_by(email=email.lower()).first()
    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_auth_token(password)


def generate_auth_token(user_email, user_password, expiration=3600*24*5):
    s = Serializer(app.config['SECRET_KEY'], expiration)
    return s.dunmps({'email': user_email, 'password': user_password}).decode('ascii')


@auth.verify_token
def verify_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    user = User.query.get(data['user_email'])
    return user


def token_encode():
    s = Serializer(app.config['SECRET_KEY'])
    token = request.args.get('token') or request.json['token']
    data = s.loads(token)
    return data


@app.route('/tokens/', methods=['POST'])
def get_token(email, password):
    if verify_password(email, password):
        return dumps({**loads(g.current_user.generate_auth_token(expiration=3600*24*5)),
                     **{'message': 'Get token successfully', 'status': 1}})
    else:
        return jsonify({'status': 0, 'message': 'There is wrong in email or password!'})


def send_async_mail(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['TP_MAIL_SUBJECT_PREFIX'] + ' ' + subject, sender=app.config['TP_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_mail, args=[app, msg])
    thr.start()
    return thr


def get_user():
    email = token_encode()['email']
    user = User.query.filter_by(user_email=email).first()
    return user


def check_user(userid):
    current_user = get_user()
    if not userid == current_user.user_id:
        return jsonify({'status': 0, 'message': 'Wrong visit'})


@app.route('/api/users/register', methods=['POST'])
def user_register():
    name = request.json['username']
    password = request.json['password']
    email = request.json['email']
    user = User(name, password, email)
    db.session.add(user)
    db.session.commit()
    send_email(email)
    return jsonify({'status': 1, 'message': 'Register successfully！'})


@app.route('/api/users/login', methods=['POST'])
def user_login():
    email = request.json['email']
    password = request.json['password']
    if verify_password(email, password):
        return jsonify({'status': 1, 'token': get_token(), 'expiration': 3600*24*5, 'message': 'Login successfully!'})
    else:
        return jsonify({'status': 0, 'message': 'Invalid email or password'})


@app.route('/api/schedules/<userid>', methods=['GET'])
@auth.login_required
def user_schedule(userid):
    check_user(userid)
    schedules = Schedule.query.filter_by(user_id=userid).all()
    data = [{
        'schedule_event':schedule.schedule_event,
        'schedule_begintime':schedule.schedule_begin,
        'schedule_endtime':schedule.schedule_end,
        'schedule_place': schedule.schedule_place
    }for schedule in schedules]
    return jsonify({'status': 1, 'message': 'All schedules about you', 'data': data})


@app.route('/api/schedules/<userid>/add', methods=['GET'])
@auth.login_required
def schedule_add(userid):
    current_user = get_user()
    if not userid == current_user.user_id:
        return jsonify({'status': 0, 'message': 'Wrong visit'})
    event = request.json['schedule_event']
    place = request.json['schedule_place']
    begintime = request.json['schedule_begintime']
    endtime = request.json['schedule_endtime']
    isddl = request.json['schedule_isddl']
    schedule = Schedule(event, place, begintime, endtime, endtime, isddl)
    db.session.add(schedule)
    db.session.commmit()
    return jsonify({'status': 1, 'message': 'Commit the schedule successfully!'})


@app.route('/api/teams/<userid>', methods=['GET'])
@auth.login_required
def team_notice(userid):
    check_user(userid)
    teams = UserTeamCharacter.query.filter_by(user_id=userid).all()
    data = [{
        'team_id': team.team_id,
        'team_name': team.team_name,
        'team_member_num': team.team_member_num
    }for team in teams]
    return jsonify({'status': 1, 'message': 'All team about you', 'data':data})


@app.route('/api/notices/<userid>', methods=['GET'])
@auth.login_required
def user_notice(userid):
    check_user(userid)
    notices = Notice.query.filter_by(user_id=userid).all()
    #应该返回所有的noticename 和 noticeid
    data = [{
        'notice_id': notice.notice_id,
        'notice_name': notice.notice_name
    }for notice in notices]
    return jsonify({'status':1, 'message': 'All notice about you', 'data':data})


@app.route('/api/votes/<userid>', methods=['GET'])
@auth.login_required
def user_vote(userid):
    check_user(userid)
    votes_user_sponsor = UserVoteSponsor.query.filter_by(user_id=userid).all()
    votes = Vote.query.filter_by(vote_id=votes_user_sponsor.vote_id).all()
    #应该返回所有的votename 、voteid
    data = [{
        'vote_id':vote.vote_id,
        'vote_name':vote.vote_name
        }for vote in votes]
    return jsonify({'status':1, 'message': 'All vote about you', 'data':data})


@app.route('/api/votes/<voteid>', methods=['GET', 'POST'])
@auth.login_required
def get_vote_and_voting(voteid):
    user = get_user()
    votes = UserVoteSponsor.query.filter_by(user_id=user.user_id).all()
    if not voteid in votes.vote_id:
        return jsonify({'status':0, 'message': 'Wrong User'})
    if request.method == 'GET':
        vote = Vote.query.filter_by(vote_id=voteid).first()
        options = VoteOption.query.filter_by(hoster_id=voteid).all()
        data = [{
            {'option_name': option.option_name}
            for option in options}]
        return jsonify({'status': 1, 'vote_name': vote.vote_name, 'data': data})
    if request.method == 'POST':
        option = request.json['option_id']
        optionnum = VoteOption.query.filter_by(host_id=voteid, option_id=option).first()
        voting = VoteOption.query.filter_by(hoster_id=voteid, option_id=option).update({'option_num': optionnum.option_num + 1})
        have_voting = UserVoteSponsor.query.filter_by(user_id=user.user_id, vote_id=voteid).update({'have_voting':1})
        db.session.add(voting)
        db.session.add(have_voting)
        db.session.commit()
        return jsonify({'status': 1, 'message': 'Voting successfully'})


@app.route('/api/team_register', methods=['POST'])
@auth.login_required
def team_registing():
    email = request.json['email']
    name = request.json['teamname']
    attr = request.json['attr']
    team = Team(email, name, attr)
    db.session.add(team)
    db.session.commit()
    the_team = Team.query.filter_by(team_maker_email=email).first()
    invitation_code = InvitationCode(the_team.team_id)
    db.session.add(invitation_code)
    db.session.commit()
    the_code = InvitationCode.query.filter_by(team_id=the_team.team_id).first()
    return jsonify({'status': 1, 'message': 'Your team register successfully', 'team_id': the_team.team_id,
                    'invitation_code': the_code.icode_value})


@app.route('/api/teamadd', methods=['POST'])
@auth.login_required
def team_adding():
    user = get_user()
    the_code = request.json['invitation_code']
    team = InvitationCode.query.filter_by(icode_value=the_code).first()
    UserTeamCharacter(user.user_id, team.team_id)
    Team.query.filter_by(team_id=team.team_id).first().update({'team_member_num': team.team_member_num+1})
    db.session.add(UserTeamCharacter)
    db.session.commit()
    return jsonify({'status': 1, 'message':' Join successfully'})


@app.route('/api/noticeadd', methods=["POST"])
@auth.login_required
def notice_add():
    pass


db.create_all()
if __name__ == '__main__':
    app.run()
