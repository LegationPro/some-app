import { User } from "@prisma/client";
import jwt from "jsonwebtoken";
import { NextFunction, Request, Response } from "express";
import { PasswordSecurity } from "@utils/hashPassword";
import { IUser, UserService } from "@services/user.service";

const verifySchema = (user: User | IUser) => {
    if (user.username && user.email && user.password) {
        return true;
    };
}

const userExists = async (user: User | IUser): Promise<string | boolean> => {
    const foundEmail = await UserService.FindUserFromEmail(user.email);
    const foundUser = await UserService.FindUserFromUsername(user.username);

    if (foundUser) {
        return "User with this username already exists";
    }

    if (foundEmail) {
        return "User with this email address already exists";
    }

    return false;
}

export const Middleware = async (req: Request, res: Response, next: NextFunction) => {
    if (req.headers.authorization) {
        const token = req.headers.authorization.replace("Bearer ", "");
        const data = jwt.decode(token) as IUser;
        const user = await UserService.FindUserFromEmail(data.email);

        if (user) {
            jwt.verify(user.refreshToken, process.env.JWT_REFRESH_SECRET!, async err => {
                if (err && err.message === "jwt expired") {
                    const userInfo = {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                    };
                    
                    const refreshToken = jwt.sign(userInfo, process.env.JWT_REFRESH_SECRET!, {expiresIn: process.env.JWT_REFRESH_EXPIRE_TIME!})
                    await UserService.UpdateRefreshToken(user.id, refreshToken);
                }
            })
        }

        jwt.verify(token, process.env.JWT_ACCESS_SECRET!, async (err, user) => {
            if (user) {
                (req as any).user = user;
                next();
            }

            if (err.message === "jwt expired") {
                const user = jwt.decode(token) as User;

                if (user && user.id && user.email && user.username) {
                    const userPayload = {
                        id: user.id,
                        email: user.email,
                        username: user.username,
                    };

                    const accessToken = jwt.sign(userPayload, process.env.JWT_ACCESS_SECRET!, {expiresIn: process.env.JWT_ACCESS_EXPIRE_TIME!});
                    (req as any).token = accessToken;
                    next();
                } else {
                    return res.status(401).send("User not authenticated");
                }
            } else {
                return res.send("User not authenticated");
            }
        })
    }
}

export const ProtectedRoute = async (req: Request, res: Response) => {
    
}

export const Signup = async (req: Request, res: Response) => {
    const user: User = req.body.user;
    const exists = await userExists(user);

    if (verifySchema(user) && !exists) {
        const hash = await PasswordSecurity.HashPassword(user.password);
        await UserService.Create({
            username: user.username,
            password: hash,
            email: user.email,
        });
        return res.status(201).send("Success");
    }

    if (exists) {
        return res.status(401).send(exists as string);
    }

    return res.status(401).send("Please provide all user credentials");
}

export const Login = async (req: Request, res: Response) => {
    const user: IUser = req.body.user;

    if (verifySchema(user)) {
        const userObject = await UserService.FindUserFromEmail(user.email);
    
        if (!userObject) {
            return res.status(401).json({ message: "User does not exist!"});
        }
    
        if (userObject && userObject.email && userObject.password && userObject.username) {
            const match = await PasswordSecurity.ComparePassword(user.password, userObject.password);
        
            if (match) {
                const userInfo = {
                    id: userObject.id,
                    username: userObject.username,
                    email: userObject.email,
                };
        
                const accessToken = jwt.sign(userInfo, process.env.JWT_ACCESS_SECRET!, {expiresIn: process.env.JWT_ACCESS_EXPIRE_TIME!});
                const refreshToken = jwt.sign(userInfo, process.env.JWT_REFRESH_SECRET!, {expiresIn: process.env.JWT_REFRESH_EXPIRE_TIME!});

                await UserService.UpdateRefreshToken(userObject.id, refreshToken);

                res.status(201).json({
                    accessToken,
                    refreshToken,
                });
            } else {
                res.status(401).json({
                    message: "Failed",
                });
            }
        }
    } else {
        res.status(401).send("Please provide all user credentials");
    }
}