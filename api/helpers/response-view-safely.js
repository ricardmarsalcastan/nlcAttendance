/**
 * @name sails&period;helpers&period;responseViewSafely
 * @description Responds with an HTML page, or 404 error if view template does not exist.
 * @function
 * @argument {external:Response} response - The Express/Sails object representing an HTTP response.
 * @argument {string} pathToView - The path to the desired view file, relative to `views/`, with no file extension or trailing slash.
 * @argument {ViewData} [locals] - Data to pass to the view template. 
 * @see {@link https://sailsjs.com/documentation/reference/response-res/res-view}, which throws server error if view template does not exist.
 * @async
 */
const fs = require("fs"); // nodejs file system access

module.exports = {

    friendlyName: "Response view safely",

    description: "Responds with an HTML page, or 404 error if view template does not exist.",

    inputs: {
        request: {
            description: "The Express/Sails object representing an HTTP request.",
            type: "ref",
            required: true
        },

        response: {
            description: "The Express/Sails object representing an HTTP response.",
            type: "ref",
            required: true
        },

        pathToView: {
            description: "The path to the desired view file relative to your app's views folder (usually views/), without the file extension, and with no trailing slash.",
            type: "string",
            required: true
        },

        locals: {
            description: "Data to pass to the view template.",
            type: "ref",
            required: false
        }
    },

    exits: {
        success: {
            description: "Response complete",
        },
    },

    fn: async function (inputs, exits) {
        fs.access(`views/${inputs.pathToView}.html`, fs.constants.F_OK, (error) => {
            if (error) return exits.success(inputs.response.notFound());

            let autoLogout = false;
            let locals = inputs.locals || {};
            if (inputs.request.cookies) {
                if (inputs.request.cookies.restAction === "edit" && (inputs.request.cookies.restModel === "student" || inputs.request.cookies.restModel === "staff")) {
                    locals.banner = "Your user profile has been updated.";
                }
                else if (inputs.request.cookies.restAction === "create" && inputs.request.cookies.restModel === "visit") {
                    locals.banner = "You are now checked in. Please remember to check out before you leave.";
                    autoLogout = true;
                }
                else if (inputs.request.cookies.restAction === "edit" && inputs.request.cookies.restModel === "visit") {
                    locals.banner = "You are now checked out. Thanks for visiting the Naylor Center.";
                    autoLogout = true;
                }
            }

            // Clear REST cookies
            inputs.response.clearCookie("restAction");
            inputs.response.clearCookie("restModel");

            if (autoLogout) {
                inputs.request.session.destroy();
                return exits.success(inputs.response.view("pages/login", locals));
            }

            return exits.success(inputs.response.view(inputs.pathToView, locals));
        });
    }

};

/**
 * Data needed to configure an EJS view.
 * @typedef {Object} ViewData
 * @property {Record} formData - The data values to populate in the view's form inputs.
 * @property {string} action - The value of the `action` atrribute for the view's &lt;form&gt; element.
 * @property {string} [...domainSelect] - HTML source for &lt;select&gt; element; property name is associated Sails model.
 */
