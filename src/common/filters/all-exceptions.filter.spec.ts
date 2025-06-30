import { Test, TestingModule } from '@nestjs/testing';
import { AllExceptionsFilter } from './all-exceptions.filter';
import { HttpAdapterHost } from '@nestjs/core';
import { HttpException, HttpStatus } from '@nestjs/common';

describe('AllExceptionsFilter', () => {
  let filter: AllExceptionsFilter;
  let httpAdapterHost: HttpAdapterHost;

  const mockHttpAdapter = {
    reply: jest.fn(),
    getRequestUrl: jest.fn(),
  };

  const mockHttpAdapterHost = {
    httpAdapter: mockHttpAdapter,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AllExceptionsFilter,
        {
          provide: HttpAdapterHost,
          useValue: mockHttpAdapterHost,
        },
      ],
    }).compile();

    filter = module.get<AllExceptionsFilter>(AllExceptionsFilter);
    httpAdapterHost = module.get<HttpAdapterHost>(HttpAdapterHost);
  });

  it('should be defined', () => {
    expect(filter).toBeDefined();
  });

  describe('catch', () => {
    it('should handle HttpException', () => {
      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);
      const host = { switchToHttp: () => ({ getRequest: () => ({}), getResponse: () => ({}) }) };

      filter.catch(exception, host as any);

      expect(mockHttpAdapter.reply).toHaveBeenCalled();
    });

    it('should handle non-HttpException', () => {
      const exception = new Error('Test error');
      const host = { switchToHttp: () => ({ getRequest: () => ({}), getResponse: () => ({}) }) };

      filter.catch(exception, host as any);

      expect(mockHttpAdapter.reply).toHaveBeenCalled();
    });
  });
});
