import { Module } from '@nestjs/common';
import { ItemStatusService } from './item-status.service';
import { ItemStatusController } from './item-status.controller';

@Module({
  providers: [ItemStatusService],
  controllers: [ItemStatusController]
})
export class ItemStatusModule {}
