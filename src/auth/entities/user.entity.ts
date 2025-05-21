import { Column, Entity, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from "typeorm";
import { UserRole } from "@moduleAuth/interfaces";

@Entity('users')
export class User{
    @PrimaryGeneratedColumn()
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
    googleId: string

    @Column({
        type: 'text',
        unique: true
    })
    email: string

    @Column({
        type: 'text',
        nullable: true
    })
    password: string

    @Column({
        type: 'text'
    })
    name: string

    @Column({
        name: 'picture_url',
        type: 'text'
    })
    pictureUrl: string

    @Column({
        name: 'is_active',
        type: 'bool',
        default: false
    })
    isActive: boolean

    @CreateDateColumn({
        name: 'created_at',
        type: 'timestamp',
        default: () => 'CURRENT_TIMESTAMP'
    })
    createdAt: Date;

    @UpdateDateColumn({ 
        name: 'updated_at',
        type: 'timestamp',
        default: () => 'CURRENT_TIMESTAMP'
      })
      updatedAt: Date;
}