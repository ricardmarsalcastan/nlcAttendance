/**
 * @module Student
 * 
 * Usage: `Sptuden` or `sails.models.Student`
 */
 
module.exports = { 
    attributes: {
        username: { type: "string", required: true, allowNull: false, unique: true },
        firstName: { type: "string", required: true, allowNull: false },
        lastName: { type: "string", required: true, allowNull: false },
        fallSport: { model: "Sport" },
        springSport: { model: "Sport" }
    },
};
