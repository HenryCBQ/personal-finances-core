import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ItemTypeModule } from './item-type/item-type.module';
import { ItemCategoryModule } from './item-category/item-category.module';
import { ItemStatusModule } from './item-status/item-status.module';
import { TransactionTypeModule } from './transaction-type/transaction-type.module';
import { AuthModule } from './auth/auth.module';
import { ItemModule } from './item/item.module';
import { TransactionModule } from './transaction/transaction.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: +process.env.DB_PORT,
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
      autoLoadEntities: true,
      synchronize: process.env.DB_SYNCHRONIZE === 'true',
    }),
    ItemTypeModule,
    ItemCategoryModule,
    ItemStatusModule,
    TransactionTypeModule,
    AuthModule,
    ItemModule,
    TransactionModule,
  ],
})
export class AppModule {}
