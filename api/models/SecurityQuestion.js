/**
 * Represents a set of security question records. 
 * @module 
 * @implements Model
 * @borrows SecurityQuestion as SecurityQuestion
 */
module.exports = {

    attributes: {
        name: { type: "string", required: true, unique: true},
    },
    
    candidateKey: "name",

    testRecords: [],

    createQuestions: async function() {
    
        for (let i = 0; i < 5; i++) {
            this.testRecords.push(await SecurityQuestion.create({
                name: `Question number ${i}`,
            }).fetch());
        }
    }
};

/**
 * A list of security questions.
 * @typedef {Record} MajorRecord
 * @property {string} name - The major's name.
 */
