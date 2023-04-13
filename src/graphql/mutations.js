const { GraphQLString } = require('graphql');
const { User } = require('../models');
const bcrypt = require('bcrypt');
const { createJWT } = require('../util/auth');


const register = {
    type: GraphQLString,
    description: 'Register a new user',
    args: {
        username: { type: GraphQLString },
        email: { type: GraphQLString },
        password: { type: GraphQLString }
    },
    async resolve(parent, args){
        const checkUser = await User.findOne({ email: args.email }).exec();
        if (checkUser){
            throw new Error("User with this email address already exists");
        }

        const { username, email, password } = args;
        const passwordHash = await bcrypt.hash(password, 10);

        const user = new User({ username, email, password: passwordHash });

        await user.save();

        const token = createJWT(user);

        return token
    }
}

const login = {
    type: GraphQLString,
    description: 'Log in a registered user',
    args: {
        email: { type: GraphQLString },
        password: { type: GraphQLString }
    },
    


    async resolve(parent, args){
        const checkUser = await User.findOne({ email: args.email }).exec();
        if (!checkUser){
            throw new Error("Email address not found");
        } else {

        const { email, password } = args;
       
        const passwordHash = await bcrypt.hash(password, 10);

        const user = new User({ username, email, password: passwordHash });

        await user.save();

        const match = await bcrypt.compare(password, user.passwordHash);

        if (match) {
            const token = createJWT(user);
            return token
        } else {
            throw new Error("Invalid password")
        }
        
        }
    }
}

module.exports = {
    register, login
}
