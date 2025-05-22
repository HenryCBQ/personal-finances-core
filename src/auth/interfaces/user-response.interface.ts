import { UserRole } from "./user-roles.interface";

export interface IUserResponse {
    id: number;
    role: UserRole;
    googleId: string | null;
    email: string;
    name: string;
    pictureUrl: string | null;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}