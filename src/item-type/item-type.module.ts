import { Module } from '@nestjs/common';
import { ItemTypeService } from './item-type.service';
import { ItemTypeController } from './item-type.controller';

@Module({
  providers: [ItemTypeService],
  controllers: [ItemTypeController]
})
export class ItemTypeModule {}
