import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use the Agg backend for rendering to PNGs
import matplotlib.pyplot as plt
import seaborn as sns


curr_dir=os.path.abspath(os.path.dirname(__file__))

#Creating a Flask instance
app=Flask(__name__, template_folder="templates")
app.secret_key="letsencrypt"
app.config['PASSWORD_HASH'] = 'sha512'

#adding the database
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///homerenovation.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False



app.config['UPLOAD_EXTENSIONS']=['.pdf']
app.config['UPLOAD_PATH']=os.path.join(curr_dir, 'static', 'pdfs')

db = SQLAlchemy()


#initialising database
db.init_app(app)
app.app_context().push()

class User(db.Model):
    __tablename__="user"
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    address = db.Column(db.String(80), nullable=True)
    pincode = db.Column(db.Integer, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_contractor = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    is_homeowner = db.Column(db.Boolean, default=False)
    avg_rating = db.Column(db.Float, default=0.0)
    rating_count = db.Column(db.Integer, default=0)
    con_file = db.Column(db.String(80), nullable=True)
    con_experience = db.Column(db.String(80), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('renovationServices.id', ondelete = "SET NULL"), nullable=True)
    service = db.relationship('RenovationServices', back_populates="contractors")

    # Relationship for requests homeowner made
    homeowner_requests = db.relationship('RenovationServiceRequest', back_populates='homeowner', foreign_keys='RenovationServiceRequest.homeowner_id')
    
    # Relationship for requests sent to contractor
    contractor_requests = db.relationship('RenovationServiceRequest', back_populates='contractor', foreign_keys='RenovationServiceRequest.contractor_id')




class RenovationServices(db.Model):
    __tablename__="renovationServices"
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(80), unique=True, nullable=False)
    service_description = db.Column(db.String(80), nullable=True)
    base_price = db.Column(db.Integer, nullable=True)
    time_required = db.Column(db.String(80), nullable=True)
    contractors = db.relationship('User', back_populates="service", cascade="all, delete")
    request = db.relationship('RenovationServiceRequest', back_populates = "service", cascade="all, delete")




class RenovationServiceRequest(db.Model):
    __tablename__="renovationServiceRequest"
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('renovationServices.id'), nullable=True)
    homeowner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contractor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    req_type = db.Column(db.String(10), nullable=False) #private/public
    description = db.Column(db.Text, nullable = True)  # Description of the renovation request
    status = db.Column(db.String(80), nullable=True) #pending, accepted, closed, rejected
    date_created = db.Column(db.Date, nullable=False, default=datetime.now().date())
    date_closed = db.Column(db.Date, nullable=True)
    rating_by_homeowner = db.Column(db.Float, default=0.0)
    review_by_homeowner = db.Column(db.String(80), nullable=True)
    service = db.relationship('RenovationServices', back_populates='request')
    homeowner = db.relationship('User', back_populates='homeowner_requests', foreign_keys=[homeowner_id])
    contractor = db.relationship('User', back_populates='contractor_requests', foreign_keys=[contractor_id])


def create_admin():
    with app.app_context():  
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            admin_user = User(
                user_name='admin',  # Default username
                password=generate_password_hash('12345678'),  # Strong password
                is_admin=True,
                is_approved=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print('Admin user created successfully.')


with app.app_context():
    db.create_all()
    create_admin()


@app.route("/")
def home():
    return render_template('index.html')



@app.route("/rwu_admin", methods = ["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        admin = User.query.filter_by(is_admin=True).first()
        if admin and check_password_hash(admin.password, password):
            session['username'] = username
            session['is_admin'] = True
            flash('Login successful!', 'success')
            return redirect("/admin_dashboard")
    return render_template('admin_login.html')


@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(user_name=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_contractor'] = user.is_contractor
            session['is_homeowner'] = user.is_homeowner
            session['username'] = user.user_name
            if user.is_contractor:
                user_type="contractor"
                if user.is_approved==False:
                    flash('Please wait for admin approval', 'danger')
                    return redirect('/login')
                if user.service_id == None:
                    flash('Your service is not available now. Please create a new account with other service.', 'danger')
                    return redirect('/login')
                return redirect('/'+user_type+'_dashboard')
            if user.is_homeowner:
                user_type="homeowner"
                flash('Login successful!', 'success')
                return redirect('/'+user_type+'_dashboard')
        flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')


@app.route("/contractor_register", methods=["GET", "POST"])
def contractor_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address=request.form['address']
        pincode = request.form['pincode']
        con_file = request.files['con_file']
        con_experience = request.form['con_experience']
        service = request.form['service']
        service_id = RenovationServices.query.filter_by(service_name=service).first().id
        user = User.query.filter_by(user_name=username).first()
        if user:
            flash('User already exists. Please choose a different username.', 'danger')
            return redirect('/contractor_register')
        file_name=secure_filename(con_file.filename)
        if file_name!="":
            file_ext=os.path.splitext(file_name)[1]
            renamed_file_name=username+file_ext
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            con_file.save(os.path.join(app.config['UPLOAD_PATH'], renamed_file_name))
        user = User(user_name=username, password=generate_password_hash(password), is_contractor=True, address=address, pincode=pincode, con_file=renamed_file_name, con_experience=con_experience, service_id = service_id)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect('/login')
    services = RenovationServices.query.all()
    return render_template('contractor_register.html', services = services)



#creating route for homeowner register
@app.route("/homeowner_register", methods=["GET", "POST"])
def homeowner_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address=request.form['address']
        pincode = request.form['pincode']
        user = User.query.filter_by(user_name=username).first()
        if user:
            flash('User already exists. Please choose a different username.', 'danger')
            return redirect('/homeowner_register')
        user = User(user_name=username, password=generate_password_hash(password), is_homeowner=True, is_approved=True, address=address, pincode=pincode)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect('/login')
    return render_template('homeowner_register.html')

@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    session.pop('is_contractor', None)
    session.pop('is_homeowner', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))





@app.route("/admin_dashboard", methods=["GET", "POST"])
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    services = RenovationServices.query.all()
    requests = RenovationServiceRequest.query.all()
    unapproved_contractors = User.query.filter_by(is_contractor=True, is_approved=False).all()
    return render_template("admin_dashboard.html", services=services, requests=requests, unapproved_contractors=unapproved_contractors, admin_name = session['username'])






@app.route("/admin_dashboard/create_service", methods = ["GET", "POST"])
def create_service():
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    if request.method == "POST":
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        time_required = request.form['time_required']
        service = RenovationServices(service_name=name, service_description=description, base_price=price, time_required=time_required)
        db.session.add(service)
        db.session.commit()
        flash('Service created successfully', 'success')
        return redirect('/admin_dashboard')
    return render_template('create_service.html', admin_name = session['username'])


#creating route to edit a service
@app.route("/admin_dashboard/edit_service/<int:service_id>", methods = ["GET", "POST"])
def edit_service(service_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    service = RenovationServices.query.get(service_id)
    if request.method == "POST":
        service.service_name = request.form['name']
        service.service_description = request.form['description']
        service.base_price = request.form['price']
        service.time_required = request.form['time_required']
        db.session.commit()
        flash('Service updated successfully', 'success')
        return redirect('/admin_dashboard')
    return render_template('edit_service.html', service=service, admin_name = session['username'])



#creating a route to delete a service
@app.route("/admin_dashboard/delete_service/<int:service_id>", methods = ["GET", "POST"])
def delete_service(service_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    service = RenovationServices.query.get(service_id)
    #handling case that if service is deleted, then unapprove the contractors of that service
    approved_contractors = User.query.filter_by(is_contractor=True, is_approved=True, service_id=service_id).all()
    for approved_contractor in approved_contractors:
        approved_contractor.is_approved = False
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully', 'success')
    return redirect('/admin_dashboard')

#creating a route to view details of unapproved contractor
@app.route("/admin_dashboard/view_contractor/<int:contractor_id>", methods = ["GET", "POST"])
def view_contractor(contractor_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    user = User.query.get(contractor_id)
    return render_template('view_contractor.html', user=user, admin_name = session['username'])


#creating a route to approve a contractor 
@app.route("/admin_dashboard/approve_contractor/<int:contractor_id>", methods = ["GET", "POST"])
def approve_contractor(contractor_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    user = User.query.get(contractor_id)
    if user.service_id == None:
        flash('Contractor does not have a service. Reject request', 'danger')
        return redirect('/admin_dashboard')
    user.is_approved = True
    db.session.commit()
    flash('Contractor approved successfully', 'success')
    return redirect('/admin_dashboard')


@app.route("/admin_dashboard/reject_contractor/<int:contractor_id>", methods = ["GET", "POST"])
def reject_contractor(contractor_id):
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    user = User.query.get(contractor_id)
    if user:
        pdf_file_name =user.con_file
        if pdf_file_name:
            full_pdf_file_path = os.path.join(app.config['UPLOAD_PATH'], pdf_file_name)
            if os.path.exists(full_pdf_file_path):
                try:
                    os.remove(full_pdf_file_path)
                    print(f"Deleted PDF file: {full_pdf_file_path}")
                except Exception as e:
                    print(f"Error deleting PDF file: {e}")
            else:
                print(f"File not found: {full_pdf_file_path}")
        db.session.delete(user)
        db.session.commit()

    flash('Contractor rejected & deleted successfully', 'success')
    return redirect('/admin_dashboard')

#creating route for search in admin dashboard for all types of users and services
@app.route("/admin_dashboard/search", methods=["GET", "POST"])
def admin_dashboard_search():
    if not session.get('is_admin'):
        flash('Please login first', 'danger')
        return redirect('/rwu_admin')
    search_query = request.args.get("search_query")
    search_type = request.args.get("search_type")
    if search_query:
        if search_type == "user":
            users = User.query.filter(User.user_name.like("%"+search_query+"%")).all()
            return render_template("admin_search.html", users=users, admin_name = session['username'])
        elif search_type == "service":
            services = RenovationServices.query.filter(RenovationServices.service_name.like("%"+search_query+"%")).all()
            return render_template("admin_search.html", services=services, admin_name = session['username'])
    else:
        users = User.query.filter(User.is_approved == True).all()
        services = RenovationServices.query.all()
        return render_template("admin_search.html", users=users, services=services, admin_name = session['username'])



#creating route for admin summary
@app.route("/admin_dashboard/summary", methods =["GET", "POST"])
def admin_summary():
    homeowner_count = User.query.filter_by(is_homeowner=True).count()
    contractor_count = User.query.filter_by(is_contractor = True).count()

    accepted_count = RenovationServiceRequest.query.filter_by(status="accepted").count()
    rejected_count = RenovationServiceRequest.query.filter_by(status="rejected").count()
    closed_count = RenovationServiceRequest.query.filter_by(status="closed").count()
    pending_count = RenovationServiceRequest.query.filter_by(status="pending").count()
    img_1 = os.path.join(curr_dir, "static", "images", "img_1.png")
    img_2 = os.path.join(curr_dir, "static", "images", "img_2.png")
    roles = ['Homeowners', 'Contractors']
    counts = [homeowner_count, contractor_count]
    plt.figure(figsize=(6, 4))
    sns.barplot(x=roles, y=counts)
    plt.title('Number of Users by Role')
    plt.xlabel('User Role')
    plt.ylabel('Count')
    plt.savefig(img_1, format='png')


    # Pie chart for request status
    labels = ['Accepted', 'Rejected', 'Closed', 'Pending']
    sizes = [accepted_count, rejected_count, closed_count, pending_count]
    colors = ['#4CAF50', '#F44336', '#FFC107', '#03A9F4']
    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('Request Status Distribution')

    plt.savefig(img_2, format='png')



    return render_template("admin_summary.html", admin_name = session['username'], homeowner_count=homeowner_count, contractor_count=contractor_count, accepted_count=accepted_count, rejected_count=rejected_count, closed_count=closed_count, pending_count=pending_count)




#creating route for contractor dashboard where we show all requests to that contractor and closed requests
@app.route("/contractor_dashboard", methods=["GET", "POST"])
def contractor_dashboard():
    if not session['is_contractor']:
        flash('Please login first', 'danger')
        return redirect('/login')
    cid = User.query.filter_by(user_name=session['username']).first().id
    contractor = User.query.filter_by(id=cid).first()
    if contractor.is_approved == False:
        flash('Please wait for admin approval', 'danger')
        return redirect('/login')
    #pending private requests of contractor
    pending_requests = RenovationServiceRequest.query.filter_by(contractor_id = cid, status="pending", req_type= "private").all()
    accepted_requests = RenovationServiceRequest.query.filter_by(contractor_id = cid, status="accepted").all()
    closed_requests = RenovationServiceRequest.query.filter_by(contractor_id = cid, status="closed").all()
    return render_template("contractor_dashboard.html", contractor_name = session['username'], pending_requests=pending_requests, active_requests = accepted_requests, closed_requests = closed_requests,username = session['username'])



#creating route to accept a pending request by contractor
@app.route("/contractor_dashboard/accept_request/<int:request_id>", methods = ["GET", "POST"])
def accept_request(request_id):
    if not session['is_contractor']:
        flash('Please login first', 'danger')
        return redirect('/login')
    new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
    new_request.status ="accepted"
    db.session.commit()
    flash('Request accepted successfully', 'success')
    return redirect('/contractor_dashboard')


#creating a route to reject a pending request by contractor
@app.route("/contractor_dashboard/reject_request/<int:request_id>", methods = ["GET", "POST"])
def reject_request(request_id):
    if not session['is_contractor']:
        flash('Please login first', 'danger')
        return redirect('/login')
    new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
    new_request.status = "rejected"
    db.session.commit()
    flash('Request rejected successfully', 'success')
    return redirect('/contractor_dashboard')



#creating route to show homeowner dashboard with details of all services which has any contractor approved, and service history with their status
@app.route("/homeowner_dashboard", methods=["GET", "POST"])
def homeowner_dashboard():
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    homeowner = User.query.filter_by(user_name=session['username']).first()
    services = RenovationServices.query.join(User).filter(User.is_approved == True).all()
    service_history = RenovationServiceRequest.query.filter_by(homeowner_id = homeowner.id).filter(RenovationServiceRequest.contractor_id.is_not(None)).all()
    return render_template("homeowner_dashboard.html", username = session['username'], services=services, service_history = service_history, homeowner_name = session['username'])

#creating a route to create a request in a service
@app.route("/homeowner_dashboard/create_request/<int:service_id>", methods=["GET", "POST"])
def create_request(service_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')    
    if request.method == "POST":
        contractor = request.form['contractor']
        description = request.form['description']
        cid = User.query.filter_by(user_name = contractor).first().id
        homeowner_id = User.query.filter_by(user_name=session['username']).first().id
        new_request = RenovationServiceRequest(homeowner_id = homeowner_id, contractor_id = cid, service_id = service_id, description = description, req_type = "private", status = "pending")
        db.session.add(new_request)
        db.session.commit()
        flash('Request sent successfully', 'success')
        return redirect('/homeowner_dashboard')
    service = RenovationServices.query.get(service_id)
        #getting list of contractors associated with that service
    contractors = User.query.filter_by(is_contractor=True, is_approved = True, service_id = service_id).all()
    return render_template("create_request.html", service=service, homeowner_name = session['username'], contractors = contractors)




#creating a route to edit a request
@app.route("/homeowner_dashboard/edit_request/<int:request_id>", methods=["GET", "POST"])
def edit_request(request_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    if request.method == "POST":
        description = request.form['description']
        new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
        new_request.description = description
        db.session.commit()
        flash('Request updated successfully', 'success')
        return redirect('/homeowner_dashboard')
    new_request = RenovationServiceRequest.query.get(request_id)
    if new_request.status == "closed" or new_request.status == "rejected" or new_request.status == "accepted":
        flash('Request cannot be edited as it is already %s. Better create new request!' % new_request.status, 'danger')
        return redirect('/homeowner_dashboard')
    return render_template("edit_request.html", new_request = new_request, homeowner_name = session['username'])


#creating route to delete a service request sent by homeowner
@app.route("/homeowner_dashboard/delete_request/<int:request_id>", methods = ["GET", "POST"])
def delete_request(request_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
    db.session.delete(new_request)
    db.session.commit()
    flash('Request deleted successfully', 'success')
    return redirect('/homeowner_dashboard')


#creating route to create open pool request from contractors of a praticular service
@app.route("/homeowner_dashboard/create_open_pool_request/<int:service_id>", methods = ["GET", "POST"])
def create_open_pool_request(service_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    homeowner_id = User.query.filter_by(user_name=session['username']).first().id
    new_request = RenovationServiceRequest(homeowner_id = homeowner_id, service_id = service_id, req_type = "public", status = "pending")
    db.session.add(new_request)
    db.session.commit()
    flash('Request sent successfully', 'success')
    return redirect('/homeowner_dashboard')




#creating a route for closing a request which then open a page to rate and review the service by the contractor and on submitting the review and rating, the request gets closed.
@app.route("/homeowner_dashboard/close_request/<int:request_id>", methods = ["GET", "POST"])
def close_request(request_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    if request.method == "POST":
        rating = request.form.get("rating")
        review = request.form.get("review")
        print(review)
        new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
        new_request.status = "closed"
        new_request.rating_by_homeowner = int(rating)
        new_request.review_by_homeowner = review
        new_request.date_closed = datetime.now().date()
        cont_review_update = User.query.filter_by(id = new_request.contractor_id).first()
        temp = cont_review_update.rating_count
        cont_review_update.rating_count = cont_review_update.rating_count + 1
        cont_review_update.avg_rating = (cont_review_update.avg_rating*temp + int(rating))/cont_review_update.rating_count
        db.session.commit()
        print(review)
        flash('Request closed successfully', 'success')
        return redirect('/homeowner_dashboard')
    new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
    contractor = new_request.contractor.user_name
    service = new_request.service.service_name
    return render_template("rating_review.html", contractor = contractor, service = service, request_id = request_id, homeowner_name = session['username'])


#creating route to show open requests by homeowners in contractor dashboard
@app.route("/contractor_dashboard/open_requests", methods=["GET", "POST"])
def open_requests():
    if not session['is_contractor']:
        flash('Please login first', 'danger')
        return redirect('/login')
    contractor= User.query.filter_by(user_name=session['username']).first()
    new_requests = RenovationServiceRequest.query.filter_by(status = "pending", req_type = "public", service_id = contractor.service_id).filter(RenovationServiceRequest.contractor_id == None).all()
    sent_requests = RenovationServiceRequest.query.filter_by(status = "pending", req_type = "public", service_id = contractor.service_id, contractor_id = contractor.id).all()
    return render_template("open_requests_contractor.html", new_requests = new_requests, sent_requests = sent_requests, contractor_name = session['username'])

#creating bidding sending by the contractor as new request for a given request id
@app.route("/contractor_dashboard/bid_request/<int:request_id>", methods = ["GET", "POST"])
def bid_request(request_id):
    if not session['is_contractor']:
        flash('Please login first', 'danger')
        return redirect('/login')
    if request.method == "POST":
        description = request.form['description']
        contractor_id = User.query.filter_by(user_name = session['username']).first().id
        service_id = User.query.filter_by(id = contractor_id).first().service_id
        homeowner_id = RenovationServiceRequest.query.filter_by(id = request_id).first().homeowner_id
        new_request = RenovationServiceRequest(homeowner_id = homeowner_id, contractor_id = contractor_id, service_id = service_id, description = description, req_type = "public", status = "pending")
        db.session.add(new_request)
        db.session.commit()
        flash('Bid request sent successfully', 'success')
        return redirect('/contractor_dashboard')
    homeowner_id = RenovationServiceRequest.query.filter_by(id = request_id).first().homeowner_id
    new_request = RenovationServiceRequest.query.get(homeowner_id)
    return render_template("open_request_contractor.html", new_request = new_request, contractor_name = session['username'])


#creating route to see all the public requests bidding request sent by contractor to homeowner in homeowner dashboard
@app.route("/homeowner_dashboard/bidding_requests", methods=["GET", "POST"])
def bidding_requests():
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    homeowner_id = User.query.filter_by(user_name=session['username']).first().id
    new_requests = RenovationServiceRequest.query.filter_by(status = "pending", req_type = "public", homeowner_id = homeowner_id).filter(RenovationServiceRequest.contractor_id.is_not(None)).all()
    return render_template("open_requests_homeowner.html", new_requests = new_requests, homeowner_name = session['username'])



#creating route to accept the bidding request sent by contractor to homeowner by homeowner in homeowner dashboard and deleting remaining contractors requests for same service
@app.route("/homeowner_dashboard/reject_request/<int:request_id>", methods = ["GET", "POST"])
def reject_request_homeowner(request_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
    db.session.delete(new_request)
    db.session.commit()
    flash('Request rejected & deleted successfully', 'success')
    return redirect('/homeowner_dashboard')


#creating route to accept the bidding request sent by contractor to homeowner by homeowner in homeowner dashboard and deleting remaining contractors requests for same service
@app.route("/homeowner_dashboard/accept_request/<int:request_id>", methods = ["GET", "POST"])
def accept_request_homeowner(request_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    new_request = RenovationServiceRequest.query.filter_by(id = request_id).first()
    new_request.status = "accepted"
    new_request.date_accepted = datetime.now().date()
    old_request = RenovationServiceRequest.query.filter_by(homeowner_id = new_request.homeowner_id, req_type = "public", service_id = new_request.service_id, status = "pending").all()
    for i in old_request:
        db.session.delete(i)
    db.session.commit()
    flash('Request accepted successfully', 'success')
    return redirect('/homeowner_dashboard')




 #creating a route to show contractor profile with all the contractor details like reviews, ratings in homeowner dashboard
@app.route("/homeowner_dashboard/contractor_profile/<int:contractor_id>", methods = ["GET", "POST"])
def contractor_profile(contractor_id):
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    new_contractor = User.query.filter_by(id = contractor_id).first()
    reviews = RenovationServiceRequest.query.filter(RenovationServiceRequest.contractor_id == new_contractor.id, RenovationServiceRequest.status == "closed").all()
    return render_template("contractor_profile.html", new_contractor = new_contractor, reviews = reviews, homeowner_name = session['username'])



#creating a route to search by pincode, service name, address, etc in homeowner dashboard in a single page
@app.route("/homeowner_dashboard/search", methods = ["GET", "POST"])
def homeowner_search():
    if not session['is_homeowner']:
        flash('Please login first', 'danger')
        return redirect('/login')
    search_query = request.args.get("search_query")
    search_type = request.args.get("search_type")
    if search_query:
        if search_type == "pincode":
            services = RenovationServices.query.join(User).filter(User.is_approved == True, User.pincode.like("%"+search_query+"%")).all()
        elif search_type == "service_name":
            services = RenovationServices.query.filter(RenovationServices.service_name.like("%"+search_query+"%")).all()
        elif search_type == "address":
            services = RenovationServices.query.join(User).filter(User.is_approved == True, User.address.like("%"+search_query+"%")).all()
    else:
        services = RenovationServices.query.join(User).filter(User.is_approved == True).all()
    return render_template("homeowner_search.html", services = services, homeowner_name = session['username'])


#creating route for search of all public requests pending requests in contractor dashboard based on its service based on pincode, location, address, etc, and see homeowner name
@app.route("/contractor_dashboard/search", methods = ["GET", "POST"])
def contractor_search():
    if not session['is_contractor']:
        flash('Please login first', 'danger')
        return redirect('/login')
    contractor  = User.query.filter_by(user_name = session['username']).first()
    search_query = request.args.get("search_query")
    search_type = request.args.get("search_type")
    onclause = RenovationServiceRequest.homeowner_id == User.id
    if search_query:
        if search_type == "pincode":
            service_requests = RenovationServiceRequest.query.join(User, onclause).filter(User.is_homeowner == True, User.pincode.like("%"+search_query+"%"), RenovationServiceRequest.req_type == "public", RenovationServiceRequest.status == "pending", RenovationServiceRequest.contractor_id == None, RenovationServiceRequest.service_id == contractor.service_id).all()
        elif search_type == "address":
            service_requests = RenovationServiceRequest.query.join(User, onclause).filter(User.is_homeowner == True, User.address.like("%"+search_query+"%"), RenovationServiceRequest.req_type == "public", RenovationServiceRequest.status == "pending", RenovationServiceRequest.contractor_id == None, RenovationServiceRequest.service_id == contractor.service_id).all()
    else:
        service_requests = RenovationServiceRequest.query.join(User, onclause).filter(User.is_homeowner == True, RenovationServiceRequest.req_type == "public", RenovationServiceRequest.status == "pending", RenovationServiceRequest.contractor_id == None, RenovationServiceRequest.service_id == contractor.service_id).all()
    return render_template("contractor_search.html", service_requests = service_requests, contractor_name = session['username'])







if __name__ == '__main__':
    app.run(debug=True)