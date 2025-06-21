import { UserRole } from "./user-roles.interface";

export interface AuthUserResponse {
    id: number;
    role: UserRole;
    email: string;
    name: string;
    pictureUrl: string | null;
    isActive: boolean;
}