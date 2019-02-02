const Model = require("./furlsails/Model");

class StudentModel extends Model {
    constructor() {
        super();
    }

    /** override */
    get sails() {
        return Student;
    }

    /** override */
    async getAssociationDomains() {
        return {
            fallSport: await Sport.find(),
            springSport: await Sport.find(),
            classRank: await ClassRank.find(),
            majors: await Majors.find(),
            residentialStatus: await ResidentialStatus.find(),
        };
    }

    /** override */
    async encodeAssociations(record) {
        if (record.fallSport) {
            let fallSport = await Sport.findOne({ name: record.fallSport });
            record.fallSport = fallSport ? fallSport.id : null;
        }

        if (record.springSport) {
            let springSport = await Sport.findOne({ name: record.springSport });
            record.springSport = springSport ? springSport.id : null;
        }
        
        if (record.classRank) {
            let classRank = await ClassRank.findOne({ name: record.name });
            record.classRank = classRank ? classRank.id : null;
        }
        
        if (record.majors) {
            let majors = await Majors.findOne({ name: record.name });
            record.majors = majors ? Majors.id : null;
        }
        
        if (record.residentialStatus) {
            let residentialStatus = await ResidentialStatus.findOne({ name: record.name });
            record.residentialStatus = residentialStatus ? ResidentialStatus.id : null;
        }
    }

    /** override */
    async populateOne(id) {
        return await Student.findOne({ id }).populate("fallSport").populate("springSport").populate("classRank").populate("majors").populate("residentialStatus");
    }
}

module.exports = new StudentModel();

/* global Student, Sport, ClassRank, Majors, ResidentialStatus */
