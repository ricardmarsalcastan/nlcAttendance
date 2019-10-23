/**
 * @module
 */
/**
 * Enforces authorization rules. 
 * @function isAuthorized
 * @argument {external:Request} request - The HTTP request. 
 * @argument {external:Response} response - The HTTP response. 
 * @argument {function} proceed - The callback to indicate that the request should go through. 
 * @modifies The response, when the user's request is not authorized.
 * @async
 */
module.exports = async function (request, response, proceed) {
    let model = request.params.model;

    if (model === "controller") return proceed();

    let profileUrl = `/${request.session.role}/${request.session.userId}`;

    request.session.userProfile = await sails.helpers.populateOne(sails.models[request.session.role], request.session.userId);

    if (request.session.role === "student") {
        let visit = await Visit.find({ where: { student: request.session.userProfile.id }, limit: 1, sort: "checkInTime DESC" });
        if (visit[0]) {
            request.session.userProfile.visit = {
                id: visit[0].id,
                checkInTime: visit[0].checkInTime,
                checkOutTime: visit[0].checkOutTime,
                length: visit[0].length,
                purpose: visit[0].purpose,
                purposeAchieved: visit[0].purposeAchieved,
                tutorCourses: visit[0].tutorCourses,
                comment: visit[0].comment,
                isLengthEstimated: visit[0].isLengthEstimated,
            };
            request.session.userProfile.visit.checkedIn = request.session.userProfile.visit.checkOutTime === null;
        }
        else {
            request.session.userProfile.visit = {
                checkedIn: false
            };
        }
    }

    // Users are authorized to access their own profile ...
    if (request.path === `${profileUrl}/edit` && request.method === "GET") return proceed();
    // Users are authorized to update their own profile ...
    if (request.path === profileUrl && request.method === "POST") return proceed();

    // A profile update may be required before the user can take any other action.
    if (request.session.userProfile.forceUpdate) {
        return response.redirect(`${profileUrl}/edit`);
    }

    // Student users are authorized to ...
    if (request.session.role === "student") {
        // ... get the proper form (checkin or checkout), to be determined by the controller. 
        if (request.path === "/student/visit") return proceed();
        // ... submit the checkin form when checked out.
        if (request.path === "/visit" && request.method === "POST" && !request.session.userProfile.visit.checkedIn) return proceed();
        // ... submit the checkout form for their current visit when checked in.
        if (request.path === `/visit/${request.session.userProfile.visit.id}` && request.method === "POST" && request.session.userProfile.visit.checkedIn) return proceed();
    }

    // Staff users are authorized to ...
    if (request.session.role === "staff") {
        // ... view the staff menu.        
        if (request.path === "/staffmenu" && request.method === "GET") return proceed();
        // ... view the list of students.
        if (request.path === "/student" && request.method === "GET") return proceed();
        // ... view the list of visits.
        if (request.path === "/visit" && request.method === "GET") return proceed();
        // ... access and submit the form for registering the browser to track visits.
        if (request.path === "/browser") return proceed();
    }

    sails.log.debug(`default to forbid for ${request.session.role}, ${request.method} ${request.path}`);
    return response.forbidden();
};