const ldap = require("ldapjs");

/**
 * Routes login and logout requests. 
 * @implements Controller
 * @module
 */
let AuthController = {
    /**
     * Handles request to display a form for entering a new data record.
     * @argument {external:Request} request -  The HTTP request.
     * @argument {external:Response} response - The HTTP response.
     * @public
     * @async
     */
    loginFormRequested: async function (request, response) {
        return sails.helpers.responseViewSafely(request, response, "pages/login");
    },

    /**
     * Handles request to create a new data record using form data.
     * @argument {external:Request} request -  The HTTP request.
     * @argument {external:Response} response - The HTTP response.
     * @public
     * @async
     */
    loginFormSubmitted: async function (request, response) {
        let domain = "@dewv.edu";

        if (request.body.username.indexOf("@") < 0 && request.body.username.slice(-domain.length) !== domain) {
            request.body.username = request.body.username + domain;
        }

        request.session.username = request.body.username;

        let result;
        if (sails.config.custom.ldap) {
            result = await AuthController._ldapAuthentication(request.body.username, request.body.password);
        } else {
            result = AuthController._simulatedAuthentication(request.body.username, request.body.password);
        }

        if (result instanceof ldap.InvalidCredentialsError) {
            response.locals.banner = "Invalid username and/or password.";
            return AuthController.logout(request, response);
        } else if (result instanceof ldap.InsufficientAccessRightsError) {
            response.locals.banner = "Sorry, you are not authorized to use this system.";
            return AuthController.logout(request, response);
        } else if (result instanceof ldap.UnavailableError) {
            sails.log.debug("appeal to security question");
            // LDAP is unavailable; appeal to security question
            return response.redirect('/securityquestion'); // TODO
        }
        
        return AuthController.postAuth(request, response, result);
    },
    
    securityQuestionRequested: async function (request, response) {
        let ejsData;
        let student = await sails.models["student"].findOne({username: request.session.username});
        if (student) {
            student = await sails.helpers.populateOne(sails.models["student"], student.id);
            student.role = "student";
            ejsData = {
                user: student,
            }
            return await sails.helpers.responseViewSafely(request, response, `pages/question`, ejsData);
        }
        let staff = await sails.models["staff"].findOne({username: request.session.username});
        if (staff) {
            staff = await sails.helpers.populateOne(sails.models["staff"], staff.id);
            staff.role = "staff";
            ejsData = {
                user: staff, 
            }
            return await sails.helpers.responseViewSafely(request, response, `pages/question`, ejsData);
        }
        response.locals.banner = "Sorry, the system does not support first time logins at the moment. Please try again later. ";
        return AuthController.logout(request, response);
    },

    securityQuestionSubmitted: async function (request, response) {
        let record = await sails.models[request.body.role].find({username: request.session.username});
        record = await sails.helpers.populateOne(sails.models[request.body.role], request.body.id);
        let result = {
            role: request.body.role,
            firstName: request.body.firstName,
            lastName: request.body.lastName,
            username: request.body.username,
        }
        let string = request.body.secAnswer + record.salt;
        console.log(result);
        if (record.secAnswer === string){ return AuthController.postAuth(request, response, result); }
        response.locals.banner = "Sorry, the answer provided was incorrect. Please try again. ";
        return AuthController.logout(request, response);        
    },

    postAuth: async function (request, response, result) {

        for (const property in result) {
            request.session[property] = result[property];
        }
        console.log(result);
        let userProfile = await sails.models[request.session.role].findOrCreate({
            username: request.body.username
        }, {
            username: request.body.username,
            firstName: request.session.firstName,
            lastName: request.session.lastName,
            salt: Math.random().toString(36).replace(/[^a-z]+/g, '')
        });

        request.session.userId = userProfile.id;
        request.session.username = userProfile.username;

        if (request.session.role === "student") {
            request.session.defaultUrl = "/student/visit";
        } else if (request.session.role === "staff") {
            request.session.defaultUrl = "/visit";
        }

        request.session.save();
        return response.redirect(request.session.defaultUrl);
    },

    logout: async function (request, response) {
        request.session.destroy();
        return await sails.helpers.responseViewSafely(request, response, `pages/login`);
    },

    _ldapAuthentication: async function (username, password) {
        const ldapConfig = sails.config.custom.ldap;
        const clientOptions = ldapConfig.clientOptions;

        return new Promise((resolve) => {
            let client = ldap.createClient(clientOptions);

            client.on("error", function (error) {
                _handleError(`LDAP client error handler: ${error.message}`);
            });

            client.on("connectError", function (error) {
                _handleError(`LDAP connectError handler: ${error.message}`);
            });

            client.on("connect", function (_socket, error) {
                if (error) {
                    return _handleError(`LDAP connect handler: ${error.message}`);
                }

                client.bind(username, password, function (error) {
                    if (error) {
                        if (error instanceof ldap.InvalidCredentialsError) {
                            return resolve(error);
                        }
                        return _handleError(`LDAP bind handler: ${error.message}`);
                    }

                    // Authentication was successful. Get information about user. 
                    ldapConfig.searchOptions.filter = `(userPrincipalName=${username})`;
                    client.search(ldapConfig.searchBaseDn, ldapConfig.searchOptions, function (error, searchResponse) {
                        if (error) {
                            return _handleError(`LDAP client search: ${error.message}`);
                        }

                        searchResponse.on("error", function (error) {
                            _handleError(`LDAP search response error handler: ${error.message}`);
                        });

                        searchResponse.on("searchEntry", function (entry) {
                            client.unbind();

                            // Build result using configured aliases (e.g., "sn" -> "lastName")
                            let result = {};
                            for (let attribute of ldapConfig.searchOptions.attributes) {
                                if (ldapConfig.searchResultAliases[attribute]) {
                                    result[ldapConfig.searchResultAliases[attribute]] = entry.object[attribute];
                                }
                            }

                            // Set user role(s) based on LDAP distinguished name (dn).
                            let ldapRoles = sails.config.custom.ldap.roles;
                            for (const rule of ldapRoles) {
                                if (entry.object.dn.indexOf(rule.dnContains) >= 0) {
                                    result.role = rule.role;
                                }
                            }

                            // User must have at least one role.
                            if (!result.role) return resolve(new ldap.InsufficientAccessRightsError());

                            resolve(result);
                        });
                    });
                });
            });

            function _handleError(message) {
                // Defensive programming: not clear when/why ldapjs might error here.
                sails.log.warn(message);
                resolve(new ldap.UnavailableError());
            }
        });
    },

    _simulatedAuthentication: function (username, password) {
        if (password === "student" || password === "staff") {
            return {
                role: password,
                firstName: "First",
                lastName: "Last"
            };
        } else if (password === "neither") {
            return new ldap.InsufficientAccessRightsError();
        } else if (password === "noldap") {
            return new ldap.UnavailableError();
        }

        return new ldap.InvalidCredentialsError();
    }
};

module.exports = AuthController;
