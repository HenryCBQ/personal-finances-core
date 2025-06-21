import { Column, Entity, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, BeforeInsert, BeforeUpdate } from "typeorm";
import { UserRole } from "@moduleAuth/interfaces";

@Entity('users')
export class User{
    @PrimaryGeneratedColumn('increment')
    id: number

    @Column({
        type: 'enum',
        enum: UserRole,
        default: UserRole.USER
    })
    role: UserRole

    @Column({
        name: 'google_id',
        type: 'text',
        nullable: true,
        unique: true
    })
    googleId: string | null

    @Column({
        type: 'text',
        unique: true
    })
    email: string

    @Column({
        type: 'text',
        nullable: true,
    })
    password?: string | null

    @Column({
        type: 'text'
    })
    name: string

    @Column({
        name: 'picture_url',
        type: 'text',
        nullable: true
    })
    pictureUrl: string | null

    @Column({
        name: 'is_active',
        type: 'boolean',
        default: false
    })
    isActive: boolean;

    @Column({
        name: 'verification_token',
        type: 'text',
        nullable: true,
        select: false,
    })
    verificationToken: string | null;

    @Column({
        name: 'verification_token_expires_at',
        type: 'timestamptz',
        nullable: true,
    })
    verificationTokenExpiresAt: Date | null;

    @CreateDateColumn({
        name: 'created_at',
        type: 'timestamptz',
        default: () => 'CURRENT_TIMESTAMP'
    })
    createdAt: Date;

    @UpdateDateColumn({ 
        name: 'updated_at',
        type: 'timestamptz',
        default: () => 'CURRENT_TIMESTAMP',
        onUpdate: 'CURRENT_TIMESTAMP'
    })
    updatedAt: Date;

    @BeforeInsert()
    @BeforeUpdate()
    lowercaseEmail(){
        if (this.email) {
            this.email = this.email.toLowerCase();
        }
    }
}