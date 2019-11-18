let routes = {
    // Authentication requests
    "GET /login": "AuthController.loginFormRequested",
    "POST /login": "AuthController.loginFormSubmitted",
    "GET /logout": "AuthController.logout",
    "POST /secuirtyquestion": "AuthController.secuirtyQuestionSubmitted",
    
    // Miscellaneous requests (not CRUD operations handled via REST)
    "GET /": "MiscController.get",
    "GET /staffmenu": "MiscController.get",
    "GET /browser": "MiscController.get",
    "GET /default": "MiscController.get",
    
    // Custom logic to extend default REST handling of CRUD operations 
    "GET /student/visit": "StudentController.visitFormRequested",
    "POST /visit": "VisitController.createFormSubmitted",
    "POST /student/:id": "StudentController.editFormSubmitted",
    "POST /visit/:id": "VisitController.editFormSubmitted",
    "POST /staff/:id": "StaffController.editFormSubmitted",
    
    // Default handling of CRUD operations via REST 
    "GET /:model": "RestController.listRequested", 
    "GET /:model/new": "RestController.createFormRequested",
    "POST /:model": "RestController.createFormSubmitted",
    "GET /:model/:id/edit": "RestController.editFormRequested",
    "POST /:model/:id": "RestController.editFormSubmitted",
    
};

module.exports.routes = routes;
